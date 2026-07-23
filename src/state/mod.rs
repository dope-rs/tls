use dope_net::wire::buffered::{Buffer, Scratch};
use dope_net::{Bytes, Leased};
use shin::alert::{Alert, AlertDescription, AlertParseError};
use shin::record::{
    ContentType, HEADER_LEN, MAX_CIPHERTEXT_BODY, MAX_PLAINTEXT_BODY, PlaintextRecord, RecordError,
};
use shin::{Epoch, Event, client, server};

use buffer::Buffers;
use side::Side;
use status::{PeerClose, Phase};
use traffic::Traffic;

use crate::{clock::WallClock, error::Error};

pub(crate) mod buffer;
mod side;
pub mod status;
mod traffic;

const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HS_PLAIN: u8 = 22;
const REC_AEAD: u8 = 23;

pub struct State {
    side: Side,
    phase: Phase,
    traffic: Traffic,
    buffers: Buffers,
    peer_close: PeerClose,
}

impl State {
    pub fn new_client(config: client::Config) -> Result<Self, Error> {
        Self::new_client_with_clock(config, WallClock::System)
    }

    pub fn new_client_with_clock(config: client::Config, clock: WallClock) -> Result<Self, Error> {
        Self::new_client_with(config, clock, |_| {})
    }

    pub fn new_client_with(
        config: client::Config,
        clock: WallClock,
        configure: impl FnOnce(&mut client::Client<WallClock>),
    ) -> Result<Self, Error> {
        Self::new_client_with_buffers(config, clock, configure, Buffers::standalone()?)
    }

    pub(crate) fn new_client_with_buffers(
        config: client::Config,
        clock: WallClock,
        configure: impl FnOnce(&mut client::Client<WallClock>),
        buffers: Buffers,
    ) -> Result<Self, Error> {
        let (side, events) = Side::client(config, clock, configure)?;
        let mut state = Self::empty(side, buffers);
        state.absorb_events(events)?;
        Ok(state)
    }

    pub fn new_client_mutual(
        config: client::Config,
        cert: client::ClientCertSource,
    ) -> Result<Self, Error> {
        Self::new_client_mutual_with_clock(config, WallClock::System, cert)
    }

    pub fn new_client_mutual_with_clock(
        config: client::Config,
        clock: WallClock,
        cert: client::ClientCertSource,
    ) -> Result<Self, Error> {
        Self::new_client_with(config, clock, move |c| c.set_client_cert(cert))
    }

    pub fn new_server(config: server::ConnectionConfig) -> Result<Self, Error> {
        Self::new_server_with_clock(config, WallClock::System)
    }

    pub fn new_server_with_clock(
        config: server::ConnectionConfig,
        clock: WallClock,
    ) -> Result<Self, Error> {
        Self::new_server_with_buffers(config, clock, Buffers::standalone()?)
    }

    pub(crate) fn new_server_with_buffers(
        config: server::ConnectionConfig,
        clock: WallClock,
        buffers: Buffers,
    ) -> Result<Self, Error> {
        Ok(Self::empty(Side::server(config, clock)?, buffers))
    }

    fn seal_app(&mut self, ct: ContentType, data: &[u8]) -> Result<(), Error> {
        self.traffic
            .seal_application(self.buffers.pending_mut(), ct, data)
    }

    fn seal_handshake(&mut self, data: &[u8]) -> Result<(), Error> {
        self.traffic
            .seal_handshake(self.buffers.pending_mut(), data)
    }

    fn empty(side: Side, buffers: Buffers) -> Self {
        Self {
            side,
            phase: Phase::Handshaking,
            traffic: Traffic::default(),
            buffers,
            peer_close: PeerClose::Open,
        }
    }

    pub fn read_client_tcp(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.read_tcp_with(bytes, &mut |side, epoch, data| {
            side.read_client(epoch, data)
        })
    }

    pub fn read_server_tcp<G, V>(
        &mut self,
        bytes: &[u8],
        shard: &mut server::Shard<G, V>,
    ) -> Result<(), Error>
    where
        G: server::EarlyDataGuard,
        V: server::ClientCertVerifier,
    {
        self.read_tcp_with(bytes, &mut |side, epoch, data| {
            side.read_server(epoch, data, shard)
        })
    }

    fn read_tcp_with(
        &mut self,
        bytes: &[u8],
        read: &mut impl FnMut(&mut Side, Epoch, &[u8]) -> Result<Vec<Event>, shin::Error>,
    ) -> Result<(), Error> {
        let mut rest = bytes;
        loop {
            let take = self.buffers.append_recv(rest)?;
            rest = &rest[take..];
            while self.consume_one_record(read)? {}
            if rest.is_empty() {
                return Ok(());
            }
            if take == 0 {
                return Err(Error::Record(RecordError::BodyTooLarge));
            }
        }
    }

    pub fn try_read_client_tcp(&mut self, bytes: &[u8]) -> bool {
        bytes.is_empty() || self.read_client_tcp(bytes).is_ok()
    }

    pub fn try_read_server_tcp<G, V>(
        &mut self,
        bytes: &[u8],
        shard: &mut server::Shard<G, V>,
    ) -> bool
    where
        G: server::EarlyDataGuard,
        V: server::ClientCertVerifier,
    {
        bytes.is_empty() || self.read_server_tcp(bytes, shard).is_ok()
    }

    pub fn pending_send_slice(&self) -> &[u8] {
        self.buffers.pending()
    }

    pub fn consume_pending_send(&mut self, n: usize) {
        self.buffers.consume_pending(n);
    }

    pub fn pull_send(&mut self) -> Vec<u8> {
        self.buffers.take_pending()
    }

    pub fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, Error> {
        let consumed =
            self.traffic
                .write_application(self.phase, self.buffers.pending_mut(), plaintext)?;
        self.maybe_auto_key_update()?;
        Ok(consumed)
    }

    pub(crate) fn write_app_into(
        &mut self,
        output: &mut Buffer<Scratch>,
        plaintext: &[u8],
    ) -> Result<usize, Error> {
        let consumed = self
            .traffic
            .write_application(self.phase, output, plaintext)?;
        self.maybe_auto_key_update()?;
        Ok(consumed)
    }

    fn maybe_auto_key_update(&mut self) -> Result<(), Error> {
        if self.traffic.needs_key_update()
            && !self.is_closed()
            && self.traffic.key_update_fits(self.buffers.pending_spare())
        {
            self.send_key_update(false)?;
        }
        Ok(())
    }

    pub fn send_key_update(&mut self, request_update: bool) -> Result<(), Error> {
        if !self.is_established() {
            return Err(Error::NotEstablished);
        }
        let events = self.side.send_key_update(request_update)?;
        self.absorb_events(events)
    }

    pub fn send_close_notify(&mut self) -> Result<(), Error> {
        self.seal_closing_alert(Alert::close_notify())
    }

    pub fn send_fatal_alert(&mut self, desc: AlertDescription) -> Result<(), Error> {
        self.seal_closing_alert(Alert::fatal(desc))
    }

    fn seal_closing_alert(&mut self, alert: Alert) -> Result<(), Error> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        if !self.traffic.application_ready() {
            return Err(Error::NotEstablished);
        }
        self.seal_app(ContentType::Alert, &alert.body())?;
        self.phase = Phase::Closed;
        Ok(())
    }

    pub fn can_close_notify(&self) -> bool {
        matches!(self.phase, Phase::Established | Phase::PeerClosed)
            && self.traffic.application_ready()
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

    pub fn pull_app(&mut self) -> Option<Vec<u8>> {
        self.buffers.take_vec()
    }

    pub(crate) fn pull_leased_app(&mut self) -> Option<Bytes<Leased>> {
        self.buffers.take_leased()
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
        self.side.selected_alpn()
    }

    fn consume_one_record(
        &mut self,
        read: &mut impl FnMut(&mut Side, Epoch, &[u8]) -> Result<Vec<Event>, shin::Error>,
    ) -> Result<bool, Error> {
        if self.is_closed() {
            return Ok(false);
        }
        let view = self.buffers.recv();
        if view.len() < HEADER_LEN {
            return Ok(false);
        }
        let outer = view[0];
        let body_len = u16::from_be_bytes([view[3], view[4]]) as usize;
        if body_len > MAX_CIPHERTEXT_BODY {
            return Err(Error::Record(RecordError::BodyTooLarge));
        }
        let total = HEADER_LEN + body_len;
        if view.len() < total {
            return Ok(false);
        }

        match outer {
            REC_CCS => self.handle_ccs(total),
            REC_ALERT => self.handle_alert(total),
            REC_HS_PLAIN => self.handle_handshake_plaintext(total, read),
            REC_AEAD => self.handle_aead(total, read),
            _ => Err(Error::UnexpectedRecord),
        }
    }

    fn handle_ccs(&mut self, total: usize) -> Result<bool, Error> {
        self.buffers.consume_recv(total);
        Ok(true)
    }

    fn handle_alert(&mut self, total: usize) -> Result<bool, Error> {
        let parsed = Alert::parse(self.buffers.recv().get(HEADER_LEN..total).unwrap_or(&[]));
        self.buffers.consume_recv(total);
        self.classify_alert(parsed, false)
    }

    fn classify_alert(
        &mut self,
        parsed: Result<Alert, AlertParseError>,
        encrypted: bool,
    ) -> Result<bool, Error> {
        let alert = match parsed {
            Ok(a) => a,
            Err(_) => {
                self.phase = Phase::Closed;
                self.peer_close = PeerClose::Fatal(AlertDescription::DecodeError);
                return Err(Error::MalformedAlert);
            }
        };
        if encrypted && alert.description == AlertDescription::CloseNotify {
            self.peer_close = PeerClose::CloseNotify;
            self.phase = if self.traffic.application_ready() {
                Phase::PeerClosed
            } else {
                Phase::Closed
            };
            Ok(false)
        } else {
            self.phase = Phase::Closed;
            self.peer_close = PeerClose::Fatal(alert.description);
            Err(Error::PeerAlert(alert.description))
        }
    }

    fn handle_handshake_plaintext(
        &mut self,
        total: usize,
        read: &mut impl FnMut(&mut Side, Epoch, &[u8]) -> Result<Vec<Event>, shin::Error>,
    ) -> Result<bool, Error> {
        if total > HEADER_LEN + MAX_PLAINTEXT_BODY {
            return Err(Error::Record(RecordError::BodyTooLarge));
        }
        let (result, consumed) = {
            let view = self.buffers.recv();
            let (rec, consumed) =
                PlaintextRecord::parse(&view[..total])?.ok_or(Error::UnexpectedRecord)?;
            (read(&mut self.side, Epoch::Plaintext, rec.body), consumed)
        };
        self.buffers.consume_recv(consumed);
        self.finish_read(result)?;
        Ok(true)
    }

    fn handle_aead(
        &mut self,
        total: usize,
        read: &mut impl FnMut(&mut Side, Epoch, &[u8]) -> Result<Vec<Event>, shin::Error>,
    ) -> Result<bool, Error> {
        let handshake_epoch = if self.is_handshaking() && self.traffic.handshake_ready() {
            Epoch::Handshake
        } else {
            Epoch::Application
        };
        let opened = self
            .traffic
            .opener(self.phase)?
            .open(&mut self.buffers.recv_mut()[..total]);
        let (inner_type, range, consumed) = match opened {
            Ok(Some(v)) => v,
            Ok(None) => return Err(Error::UnexpectedRecord),
            Err(e) => {
                let desc = match e {
                    RecordError::UnexpectedChangeCipherSpec => AlertDescription::UnexpectedMessage,
                    _ => AlertDescription::BadRecordMac,
                };
                self.stage_fatal_alert(desc);
                self.phase = Phase::Closed;
                return Err(Error::Record(e));
            }
        };

        match inner_type {
            ContentType::ApplicationData => {
                if !range.is_empty() && !self.buffers.extend_incoming(range) {
                    self.buffers.consume_recv(consumed);
                    return self.fatal_overflow();
                }
                self.buffers.consume_recv(consumed);
                self.side.note_application_data();
            }
            ContentType::Handshake => {
                let result = read(&mut self.side, handshake_epoch, &self.buffers.recv()[range]);
                self.buffers.consume_recv(consumed);
                self.finish_read(result)?;
            }
            ContentType::Alert => {
                let parsed = Alert::parse(&self.buffers.recv()[range]);
                self.buffers.consume_recv(consumed);
                return self.classify_alert(parsed, true);
            }
            ContentType::ChangeCipherSpec => {
                self.buffers.consume_recv(consumed);
            }
        }
        Ok(true)
    }

    fn fatal_overflow(&mut self) -> Result<bool, Error> {
        self.stage_fatal_alert(AlertDescription::RecordOverflow);
        self.phase = Phase::Closed;
        Err(Error::ReceiveOverflow)
    }

    fn stage_fatal_alert(&mut self, desc: AlertDescription) {
        let alert = Alert::fatal(desc);
        if self.traffic.application_ready() {
            let _ = self.seal_app(ContentType::Alert, &alert.body());
        } else {
            let _ = self
                .buffers
                .encode_plaintext(ContentType::Alert, &alert.body());
        }
    }

    fn finish_read(&mut self, result: Result<Vec<Event>, shin::Error>) -> Result<(), Error> {
        let evs = match result {
            Ok(evs) => evs,
            Err(e) => {
                self.stage_fatal_alert(e.alert().description);
                self.phase = Phase::Closed;
                return Err(Error::Handshake(e));
            }
        };
        self.absorb_events(evs)
    }

    fn absorb_events(&mut self, events: Vec<Event>) -> Result<(), Error> {
        for e in events {
            match e {
                Event::Send { epoch, data } => match epoch {
                    Epoch::Plaintext => self
                        .buffers
                        .encode_plaintext(ContentType::Handshake, &data)?,
                    Epoch::Handshake => self.seal_handshake(&data)?,
                    Epoch::Application => self.seal_app(ContentType::Handshake, &data)?,
                    Epoch::EarlyData => return Err(Error::EarlyDataUnsupported),
                },
                Event::KeysReady {
                    epoch,
                    read_secret,
                    write_secret,
                } => {
                    self.traffic.install(
                        epoch,
                        read_secret.as_slice(),
                        write_secret.as_slice(),
                        self.side.cipher_suite(),
                    )?;
                }
                Event::KeyUpdate { direction, secret } => {
                    self.traffic
                        .update(direction, secret.as_slice(), self.side.cipher_suite())?;
                }
                Event::PeerExtension { .. } => {}
                Event::NewSessionTicket { .. } | Event::ResumptionSecret { .. } => {}
                Event::ZeroRttKeysReady { .. }
                | Event::EarlyDataAccepted
                | Event::EarlyDataRejected => {}
                Event::Done => {
                    self.phase = Phase::Established;
                }
            }
        }
        Ok(())
    }
}
