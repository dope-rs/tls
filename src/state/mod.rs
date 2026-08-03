use dope_net::wire::buffered::{Buffer, Buffered, Scratch};
use dope_net::{Bytes, Retained};
use shin::client;
use shin::client::config::{ClientCertSource, ClientCertTemplate, Config, PreparedConfig};
use shin::server;
use shin::server::config::{ClientCertVerifier, ConnectionConfig, EarlyDataGuard};
use shin::wire::alert::{Alert, AlertDescription};
use shin::wire::record::ContentType;

use buffer::Buffers;
use direct::{Direct, PlainChunks};
use record::RecordState;
use sessions::{
    Client, ClientReservation, ClientSession, Pool, PooledClient, PooledServer, Server,
    ServerSession, Session,
};
use staged::Staged;
use status::{PeerClose, Phase};

use crate::{clock::WallClock, error::Error};

pub(crate) mod buffer;
#[doc(hidden)]
pub mod direct;
mod record;
pub mod sessions;
mod staged;
pub mod status;
mod traffic;

pub struct State<S: Session> {
    record: RecordState<S>,
    phase: Phase,
    buffers: Buffers,
    peer_close: PeerClose,
}

impl State<Client> {
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_clock(config, WallClock::System)
    }

    pub fn with_clock(config: Config, clock: WallClock) -> Result<Self, Error> {
        Self::with(config, clock, |_| {})
    }

    pub fn with(
        config: Config,
        clock: WallClock,
        configure: impl FnOnce(&mut client::Client<WallClock>),
    ) -> Result<Self, Error> {
        Self::with_buffers(config, clock, configure, Buffers::standalone()?)
    }

    pub fn mutual(config: Config, cert: ClientCertSource) -> Result<Self, Error> {
        Self::mutual_with_clock(config, WallClock::System, cert)
    }

    pub fn mutual_with_clock(
        config: Config,
        clock: WallClock,
        cert: ClientCertSource,
    ) -> Result<Self, Error> {
        let session = Client::mutual(config, clock, cert)?;
        Self::start(session, Buffers::standalone()?)
    }

    pub(crate) fn with_buffers(
        config: Config,
        clock: WallClock,
        configure: impl FnOnce(&mut client::Client<WallClock>),
        buffers: Buffers,
    ) -> Result<Self, Error> {
        Self::start(Client::new(config, clock, configure)?, buffers)
    }
}

impl<'d> State<PooledClient<'d>> {
    pub(crate) fn with_reservation(
        reservation: ClientReservation<'d>,
        config: PreparedConfig,
        cert: Option<ClientCertTemplate>,
        clock: WallClock,
        buffers: Buffers,
    ) -> Result<Self, Error> {
        Self::start(
            PooledClient::new_reserved(reservation, config, cert, clock),
            buffers,
        )
    }
}

macro_rules! impl_client_state {
    ([$($generics:tt)*] $session:ty) => {
impl $($generics)* State<$session> {
    fn start(session: $session, buffers: Buffers) -> Result<Self, Error> {
        let mut state = Self::empty(session, buffers);
        state
            .record
            .start_client(&mut state.phase, state.buffers.pending_output())?;
        Ok(state)
    }

    pub fn read_tcp(&mut self, bytes: &[u8], mut receive: impl FnMut(&[u8])) -> Result<(), Error> {
        Staged::new(self).read(
            bytes,
            &mut |session, epoch, data, events| session.read_into(epoch, data, events),
            &mut receive,
        )
    }

    #[doc(hidden)]
    pub fn read_tcp_in_place<'a>(&mut self, bytes: &'a mut [u8]) -> (PlainChunks<'a>, bool) {
        Direct::new(self).read_in_place(bytes, &mut |session, epoch, data, events| {
            session.read_into(epoch, data, events)
        })
    }

    #[doc(hidden)]
    pub fn read_staged_wire(
        &mut self,
        bytes: &[u8],
    ) -> (usize, Option<Bytes<Retained>>, bool, bool) {
        let read = Staged::new(self).read_one_wire(bytes, &mut |session, epoch, data, events| {
            session.read_into(epoch, data, events)
        });
        (read.consumed, read.chunk, read.keep_reading, read.ok)
    }

    pub fn try_read_tcp(&mut self, bytes: &[u8], receive: impl FnMut(&[u8])) -> bool {
        bytes.is_empty() || self.read_tcp(bytes, receive).is_ok()
    }
}
    };
}

impl_client_state!([] Client);
impl_client_state!([<'d>] PooledClient<'d>);

impl State<Server> {
    pub fn new(config: ConnectionConfig) -> Result<Self, Error> {
        Self::with_clock(config, WallClock::System)
    }

    pub fn with_clock(config: ConnectionConfig, clock: WallClock) -> Result<Self, Error> {
        Self::with_buffers(config, clock, Buffers::standalone()?)
    }

    #[doc(hidden)]
    pub fn with_runtime(
        config: ConnectionConfig,
        clock: WallClock,
        runtime: &Buffered,
    ) -> Result<Self, Error> {
        let buffers = Buffers::from_runtime(runtime);
        Self::with_buffers(config, clock, buffers)
    }

    pub(crate) fn with_buffers(
        config: ConnectionConfig,
        clock: WallClock,
        buffers: Buffers,
    ) -> Result<Self, Error> {
        Ok(Self::empty(Server::new(config, clock)?, buffers))
    }
}

impl<'d> State<PooledServer<'d>> {
    pub(crate) fn with_pool(
        config: ConnectionConfig,
        clock: WallClock,
        buffers: Buffers,
        sessions: &'d Pool<server::Server<WallClock>>,
    ) -> Result<Self, Error> {
        Ok(Self::empty(
            PooledServer::new_in(sessions, config, clock)?,
            buffers,
        ))
    }
}

macro_rules! impl_server_state {
    ([$($generics:tt)*] $session:ty) => {
impl $($generics)* State<$session> {
    pub fn read_tcp<G, V>(
        &mut self,
        bytes: &[u8],
        shard: &mut server::Shard<G, V>,
        mut receive: impl FnMut(&[u8]),
    ) -> Result<(), Error>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
    {
        Staged::new(self).read(
            bytes,
            &mut |session, epoch, data, events| session.read_into(epoch, data, shard, events),
            &mut receive,
        )
    }

    #[doc(hidden)]
    pub fn read_tcp_in_place<'a, G, V>(
        &mut self,
        bytes: &'a mut [u8],
        shard: &mut server::Shard<G, V>,
    ) -> (PlainChunks<'a>, bool)
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
    {
        Direct::new(self).read_in_place(bytes, &mut |session, epoch, data, events| {
            session.read_into(epoch, data, shard, events)
        })
    }

    #[doc(hidden)]
    pub fn read_staged_wire<G, V>(
        &mut self,
        bytes: &[u8],
        shard: &mut server::Shard<G, V>,
    ) -> (usize, Option<Bytes<Retained>>, bool, bool)
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
    {
        let read = Staged::new(self).read_one_wire(bytes, &mut |session, epoch, data, events| {
            session.read_into(epoch, data, shard, events)
        });
        (read.consumed, read.chunk, read.keep_reading, read.ok)
    }

    pub fn try_read_tcp<G, V>(
        &mut self,
        bytes: &[u8],
        shard: &mut server::Shard<G, V>,
        receive: impl FnMut(&[u8]),
    ) -> bool
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
    {
        bytes.is_empty() || self.read_tcp(bytes, shard, receive).is_ok()
    }
}
    };
}

impl_server_state!([] Server);
impl_server_state!([<'d>] PooledServer<'d>);

impl<S: Session> State<S> {
    fn empty(session: S, buffers: Buffers) -> Self {
        Self {
            record: RecordState::new(session),
            phase: Phase::Handshaking,
            buffers,
            peer_close: PeerClose::Open,
        }
    }

    fn seal_app(&mut self, content_type: ContentType, data: &[u8]) -> Result<(), Error> {
        let mut pending = self.buffers.pending_output();
        self.record
            .traffic
            .seal_application(
                pending.try_buffer().ok_or(Error::BufferUnavailable)?,
                content_type,
                data,
            )
            .map_err(Error::from)
    }

    #[doc(hidden)]
    pub fn has_staged_recv(&self) -> bool {
        !self.buffers.recv().is_empty()
    }

    #[doc(hidden)]
    pub fn staged_recv(&self) -> &[u8] {
        self.buffers.recv()
    }

    pub fn pending_send_slice(&self) -> &[u8] {
        self.buffers.pending()
    }

    pub fn consume_pending_send(&mut self, n: usize) -> Result<(), Error> {
        self.buffers
            .try_consume_pending(n)
            .then_some(())
            .ok_or(Error::InvalidBufferProgress)
    }

    pub fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, Error> {
        let mut pending = self.buffers.pending_output();
        let consumed = self.record.traffic.write_application(
            self.phase,
            pending.try_buffer().ok_or(Error::BufferUnavailable)?,
            plaintext,
        )?;
        self.maybe_auto_key_update()?;
        Ok(consumed)
    }

    pub(crate) fn write_app_into(
        &mut self,
        output: &mut Buffer<Scratch>,
        plaintext: &[u8],
    ) -> Result<usize, Error> {
        let consumed = self
            .record
            .traffic
            .write_application(self.phase, output, plaintext)?;
        self.maybe_auto_key_update()?;
        Ok(consumed)
    }

    pub(crate) fn write_app_parts_into<'a>(
        &mut self,
        output: &mut Buffer<Scratch>,
        plaintext_len: usize,
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<usize, Error> {
        let consumed = self.record.traffic.write_application_parts(
            self.phase,
            output,
            plaintext_len,
            parts,
        )?;
        self.maybe_auto_key_update()?;
        Ok(consumed)
    }

    fn maybe_auto_key_update(&mut self) -> Result<(), Error> {
        if self.record.traffic.needs_key_update()
            && !self.is_closed()
            && self
                .record
                .traffic
                .key_update_fits(self.buffers.pending_spare())
        {
            self.send_key_update(false)?;
        }
        Ok(())
    }

    pub fn send_key_update(&mut self, request_update: bool) -> Result<(), Error> {
        if !self.is_established() {
            return Err(Error::NotEstablished);
        }
        self.record.send_key_update(
            &mut self.phase,
            self.buffers.pending_output(),
            request_update,
        )
    }

    pub fn send_close_notify(&mut self) -> Result<(), Error> {
        self.seal_closing_alert(Alert::close_notify())
    }

    pub fn send_fatal_alert(&mut self, description: AlertDescription) -> Result<(), Error> {
        self.seal_closing_alert(Alert::fatal(description))
    }

    fn seal_closing_alert(&mut self, alert: Alert) -> Result<(), Error> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        if !self.record.traffic.application_ready() {
            return Err(Error::NotEstablished);
        }
        self.seal_app(ContentType::Alert, &alert.body())?;
        self.phase = Phase::Closed;
        Ok(())
    }

    pub fn can_close_notify(&self) -> bool {
        matches!(self.phase, Phase::Established | Phase::PeerClosed)
            && self.record.traffic.application_ready()
    }

    pub fn peer_close(&self) -> PeerClose {
        self.peer_close
    }

    pub fn peer_eof(&mut self) -> Result<(), Error> {
        if self.peer_close == PeerClose::Open {
            self.peer_close = PeerClose::Truncated;
            self.phase = Phase::Closed;
            return Err(Error::Truncated);
        }
        Ok(())
    }

    pub fn is_handshaking(&self) -> bool {
        self.phase == Phase::Handshaking
    }

    pub fn is_established(&self) -> bool {
        self.phase == Phase::Established
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::PeerClosed | Phase::Closed)
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        self.record.side.selected_alpn()
    }

    fn fatal_overflow(&mut self) -> Result<bool, Error> {
        self.record.stage_fatal_alert(
            &mut self.buffers.pending_output(),
            AlertDescription::RecordOverflow,
        );
        self.phase = Phase::Closed;
        Err(Error::ReceiveOverflow)
    }
}
