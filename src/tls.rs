use std::{
    io::{self, Error, ErrorKind},
    marker::PhantomData,
};

use dope_net::wire::send::{Plain, Prepared, SendStorage, Storage, Vectored};
use dope_net::wire::{
    OpenReservation, Reclaim, RuntimeLimits, Wire,
    buffered::{Buffer, Buffered, Scratch},
};
use dope_net::{Bytes, Leased};
use shin::{
    client,
    record::MAX_PLAINTEXT_BODY,
    server::{self, ClientCertVerifier, EarlyDataGuard},
};

use crate::send::{SendProtocol, Sender};
use crate::staging::{TLS_STAGING_CAP, TLS13_RECORD_OVERHEAD};
use crate::{
    clock::WallClock,
    state::{State, buffer::Buffers, status::PeerClose},
};

struct ConnectionState {
    pub tls: Option<State>,
    pub close: bool,
    close_notify_sent: bool,
}

impl ConnectionState {
    fn empty() -> Self {
        Self {
            tls: None,
            close: false,
            close_notify_sent: false,
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

pub trait ServerPolicy: sealed::Sealed + 'static {
    type Shard: 'static;

    fn read_tcp(state: &mut State, shard: &mut Self::Shard, data: &[u8]) -> bool;

    fn replace_ticket_keys(shard: &mut Self::Shard, keys: Option<shin::ticket::TicketKeys>);
}

pub struct Standard<G = server::NoGuard>(PhantomData<fn() -> G>);

impl<G> sealed::Sealed for Standard<G> {}

impl<G> ServerPolicy for Standard<G>
where
    G: EarlyDataGuard + 'static,
{
    type Shard = server::Shard<G, server::NoClientAuth>;

    fn read_tcp(state: &mut State, shard: &mut Self::Shard, data: &[u8]) -> bool {
        state.try_read_server_tcp(data, shard)
    }

    fn replace_ticket_keys(shard: &mut Self::Shard, keys: Option<shin::ticket::TicketKeys>) {
        shard.replace_ticket_keys(keys);
    }
}

pub struct Mutual<G, V>(PhantomData<fn() -> (G, V)>);

impl<G, V> sealed::Sealed for Mutual<G, V> {}

impl<G, V> ServerPolicy for Mutual<G, V>
where
    G: EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    type Shard = server::Shard<G, V>;

    fn read_tcp(state: &mut State, shard: &mut Self::Shard, data: &[u8]) -> bool {
        state.try_read_server_tcp(data, shard)
    }

    fn replace_ticket_keys(shard: &mut Self::Shard, keys: Option<shin::ticket::TicketKeys>) {
        shard.replace_ticket_keys(keys);
    }
}

pub struct ClientSetup {
    config: client::Config,
    cert: Option<client::ClientCertSource>,
}

impl ClientSetup {
    pub fn new(config: client::Config) -> Self {
        Self { config, cert: None }
    }

    pub fn mutual(config: client::Config, cert: client::ClientCertSource) -> Self {
        Self {
            config,
            cert: Some(cert),
        }
    }
}

pub trait ClientSource: 'static {
    fn next(&mut self) -> Option<ClientSetup>;
}

impl<F> ClientSource for F
where
    F: FnMut() -> Option<ClientSetup> + 'static,
{
    fn next(&mut self) -> Option<ClientSetup> {
        self()
    }
}

pub struct NoClients;

impl ClientSource for NoClients {
    fn next(&mut self) -> Option<ClientSetup> {
        None
    }
}

pub struct OnceClient(Option<ClientSetup>);

impl ClientSource for OnceClient {
    fn next(&mut self) -> Option<ClientSetup> {
        self.0.take()
    }
}

enum EndpointKind<P: ServerPolicy, S: ClientSource> {
    None,
    Server(P::Shard),
    Client(S),
}

pub struct Endpoint<P: ServerPolicy = Standard, S: ClientSource = NoClients>(EndpointKind<P, S>);

impl<P: ServerPolicy, S: ClientSource> Default for Endpoint<P, S> {
    fn default() -> Self {
        Self(EndpointKind::None)
    }
}

impl Endpoint {
    pub fn server(config: server::Config) -> Result<Self, crate::error::Error> {
        config.validate().map_err(crate::error::Error::Handshake)?;
        Ok(Self(EndpointKind::Server(server::Shard::new(config))))
    }
}

impl<G> Endpoint<Standard<G>>
where
    G: EarlyDataGuard + 'static,
{
    pub fn server_with_early_data_guard(
        config: server::Config,
        guard: G,
    ) -> Result<Self, crate::error::Error> {
        config.validate().map_err(crate::error::Error::Handshake)?;
        Ok(Self(EndpointKind::Server(
            server::Shard::with_early_data_guard(config, guard),
        )))
    }
}

impl<V> Endpoint<Mutual<server::NoGuard, V>>
where
    V: ClientCertVerifier + 'static,
{
    pub fn server_mutual(
        config: server::Config,
        auth: server::ClientAuth,
        verifier: V,
    ) -> Result<Self, crate::error::Error> {
        config.validate().map_err(crate::error::Error::Handshake)?;
        Ok(Self(EndpointKind::Server(server::Shard::with_client_auth(
            config, auth, verifier,
        ))))
    }
}

impl<G, V> Endpoint<Mutual<G, V>>
where
    G: EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    pub fn server_mutual_with_early_data_guard(
        config: server::Config,
        guard: G,
        auth: server::ClientAuth,
        verifier: V,
    ) -> Result<Self, crate::error::Error> {
        config.validate().map_err(crate::error::Error::Handshake)?;
        Ok(Self(EndpointKind::Server(
            server::Shard::with_early_data_guard_and_client_auth(config, guard, auth, verifier),
        )))
    }
}

impl Endpoint<Standard, OnceClient> {
    pub fn client(config: client::Config) -> Self {
        Self(EndpointKind::Client(OnceClient(Some(ClientSetup::new(
            config,
        )))))
    }

    pub fn client_mutual(config: client::Config, cert: client::ClientCertSource) -> Self {
        Self(EndpointKind::Client(OnceClient(Some(ClientSetup::mutual(
            config, cert,
        )))))
    }
}

impl<P, S> Endpoint<P, S>
where
    P: ServerPolicy,
    S: ClientSource,
{
    pub fn client_source(source: S) -> Self {
        Self(EndpointKind::Client(source))
    }
}

enum RuntimeMode<P: ServerPolicy, S: ClientSource> {
    None,
    Server(P::Shard),
    Client(S),
}

pub struct Runtime<P: ServerPolicy, S: ClientSource> {
    retry: Option<(Tls<P, S>, SendState)>,
    buffers: Buffered,
    mode: RuntimeMode<P, S>,
}

impl<P, S> Runtime<P, S>
where
    P: ServerPolicy,
    S: ClientSource,
{
    pub fn replace_ticket_keys(&mut self, keys: Option<shin::ticket::TicketKeys>) -> bool {
        let RuntimeMode::Server(shard) = &mut self.mode else {
            return false;
        };
        P::replace_ticket_keys(shard, keys);
        true
    }
}

pub struct Tls<P: ServerPolicy = Standard, S: ClientSource = NoClients> {
    state: ConnectionState,
    send_inflight: bool,
    _mode: PhantomData<fn() -> (P, S)>,
}

pub struct SendState(pub(crate) Buffer<Scratch>);

pub struct TlsOpen<'a, P: ServerPolicy, S: ClientSource> {
    runtime: &'a mut Runtime<P, S>,
    value: Option<(Tls<P, S>, SendState)>,
}

impl<P, S> Drop for TlsOpen<'_, P, S>
where
    P: ServerPolicy,
    S: ClientSource,
{
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            assert!(self.runtime.retry.replace(value).is_none());
        }
    }
}

impl<P, S> OpenReservation<Tls<P, S>> for TlsOpen<'_, P, S>
where
    P: ServerPolicy,
    S: ClientSource,
{
    fn commit(mut self) -> (Tls<P, S>, SendState) {
        self.value.take().unwrap()
    }
}

unsafe impl SendStorage for SendState {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<P, S> Tls<P, S>
where
    P: ServerPolicy,
    S: ClientSource,
{
    pub(crate) fn runtime_buffers(
        limits: RuntimeLimits,
        scratch_per_connection: usize,
    ) -> io::Result<Buffered> {
        Buffered::try_for_runtime(
            limits,
            scratch_per_connection,
            TLS_STAGING_CAP,
            MAX_PLAINTEXT_BODY,
        )
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))
    }

    fn open(runtime: &mut Runtime<P, S>) -> Option<(Self, SendState)> {
        let send = SendState(runtime.buffers.try_acquire_scratch()?);
        let mut state = ConnectionState::empty();
        let tls = match &mut runtime.mode {
            RuntimeMode::Server(_) => State::new_server_with_buffers(
                server::ConnectionConfig {
                    transport_params: Vec::new(),
                },
                WallClock::System,
                Buffers::try_runtime(&runtime.buffers)?,
            )
            .ok(),
            RuntimeMode::Client(source) => {
                let ClientSetup { config, cert } = source.next()?;
                State::new_client_with_buffers(
                    config,
                    WallClock::System,
                    move |client| {
                        if let Some(cert) = cert {
                            client.set_client_cert(cert);
                        }
                    },
                    Buffers::try_runtime(&runtime.buffers)?,
                )
                .ok()
            }
            RuntimeMode::None => None,
        };
        state.close = tls.is_none();
        state.tls = tls;
        Some((
            Self {
                state,
                send_inflight: false,
                _mode: PhantomData,
            },
            send,
        ))
    }

    fn ingress_decrypt(&mut self, wire_in: &[u8], read: impl FnOnce(&mut State, &[u8]) -> bool) {
        match self.state.tls.as_mut() {
            None => {
                let _ = wire_in;
                self.state.close = true;
            }
            Some(tls) => {
                if !read(tls, wire_in) {
                    self.state.close = true;
                    return;
                }
                if tls.is_closed() && tls.peer_close() != PeerClose::CloseNotify {
                    self.state.close = true;
                }
            }
        }
    }

    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        if self.state.tls.is_none() || self.send_inflight {
            return 0;
        }
        self.drain_to_egress(egress);
        if !self.is_established() {
            return 0;
        }
        let mut consumed = 0;
        while consumed < plain.len() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plain.len());
            if !Self::egress_has_record_room(egress, end - consumed) {
                break;
            }
            let n = self.seal_record(egress, &plain[consumed..end]);
            if n == 0 {
                break;
            }
            consumed += n;
        }
        consumed
    }

    fn is_established(&self) -> bool {
        self.state.tls.as_ref().is_some_and(State::is_established)
    }

    fn egress_has_record_room(egress: &Buffer<Scratch>, plaintext_len: usize) -> bool {
        egress.spare_capacity() >= plaintext_len + TLS13_RECORD_OVERHEAD
    }

    fn seal_record(&mut self, egress: &mut Buffer<Scratch>, chunk: &[u8]) -> usize {
        let Some(tls) = self.state.tls.as_mut() else {
            return 0;
        };
        let consumed = match tls.write_app_into(egress, chunk) {
            Ok(n) => n,
            Err(_) => {
                self.state.close = true;
                return 0;
            }
        };
        self.drain_to_egress(egress);
        consumed
    }

    fn drain_tls_to_egress(tls: &mut State, egress: &mut Buffer<Scratch>) {
        let spare = egress.spare_capacity();
        if spare == 0 {
            return;
        }
        let pending = tls.pending_send_slice();
        let n = pending.len().min(spare);
        if n > 0 {
            if egress.try_extend_from_slice(&pending[..n]).is_err() {
                return;
            }
            tls.consume_pending_send(n);
        }
    }

    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>) {
        if self.send_inflight {
            return;
        }
        if let Some(tls) = self.state.tls.as_mut() {
            Self::drain_tls_to_egress(tls, egress);
        }
    }

    fn propagate_close(&mut self, _egress: &mut Buffer<Scratch>) -> bool {
        self.state.close || self.peer_close() == PeerClose::CloseNotify
    }

    pub fn peer_close(&self) -> PeerClose {
        self.state
            .tls
            .as_ref()
            .map_or(PeerClose::Open, State::peer_close)
    }

    fn seal_close_notify(&mut self, egress: &mut Buffer<Scratch>) {
        if self.state.close || self.state.close_notify_sent {
            return;
        }
        let sealed = match self.state.tls.as_mut() {
            Some(tls) if tls.can_close_notify() => tls.send_close_notify().is_ok(),
            _ => false,
        };
        if sealed {
            self.state.close_notify_sent = true;
            self.drain_to_egress(egress);
        }
    }
}

impl<P, S> SendProtocol for Tls<P, S>
where
    P: ServerPolicy,
    S: ClientSource,
{
    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        self.encrypt(egress, plain)
    }

    fn propagate_close(&mut self, egress: &mut Buffer<Scratch>) -> bool {
        self.propagate_close(egress)
    }

    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>) {
        self.drain_to_egress(egress);
    }

    fn send_inflight(&mut self) -> &mut bool {
        &mut self.send_inflight
    }
}

impl<P, S> Wire for Tls<P, S>
where
    P: ServerPolicy,
    S: ClientSource,
{
    type InitConfig = Endpoint<P, S>;
    type RuntimeContext = Runtime<P, S>;
    type Open<'a> = TlsOpen<'a, P, S>;
    type Recv<'a> = Bytes<Leased>;
    type SendStorage = SendState;

    const RECLAIM: Reclaim = Reclaim::OnSubmit;

    fn holds_plain(&self, send: &Self::SendStorage) -> bool {
        !send.0.as_slice().is_empty()
    }

    fn runtime_context(
        limits: RuntimeLimits,
        config: Self::InitConfig,
    ) -> io::Result<Self::RuntimeContext> {
        Ok(Runtime {
            retry: None,
            buffers: Self::runtime_buffers(limits, 3)?,
            mode: match config.0 {
                EndpointKind::None => RuntimeMode::None,
                EndpointKind::Server(shard) => RuntimeMode::Server(shard),
                EndpointKind::Client(source) => RuntimeMode::Client(source),
            },
        })
    }

    fn prepare_open(runtime: &mut Self::RuntimeContext) -> Option<Self::Open<'_>> {
        let value = match runtime.retry.take() {
            Some(value) => value,
            None => Self::open(runtime)?,
        };
        Some(TlsOpen {
            runtime,
            value: Some(value),
        })
    }

    fn process_recv<'a>(
        &mut self,
        runtime: &mut Self::RuntimeContext,
        bytes: &'a [u8],
    ) -> Option<Self::Recv<'a>> {
        match &mut runtime.mode {
            RuntimeMode::Server(shard) => {
                self.ingress_decrypt(bytes, |state, data| P::read_tcp(state, shard, data));
            }
            RuntimeMode::Client(_) => {
                self.ingress_decrypt(bytes, State::try_read_client_tcp);
            }
            RuntimeMode::None => {
                self.state.close = true;
            }
        }
        self.state.tls.as_mut()?.pull_leased_app()
    }

    fn recv_eof(&mut self) {
        if let Some(tls) = self.state.tls.as_mut() {
            let _ = tls.peer_eof();
        }
        self.state.close = true;
    }

    fn prepare_send<'a>(
        &'a mut self,
        send: Storage<'a, Self::SendStorage>,
        plain: Plain<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.prepare(send, plain)
    }

    fn prepare_send_vectored<'a>(
        &'a mut self,
        send: Storage<'a, Self::SendStorage>,
        vectored: Vectored<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.prepare_vectored(send, vectored)
    }

    fn submit_failed(&mut self) {
        self.send_inflight = false;
    }

    fn after_send<'a>(
        &'a mut self,
        send: Storage<'a, Self::SendStorage>,
        written: usize,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.after_send(send, written)
    }

    fn flush_pending<'a>(&'a mut self, send: Storage<'a, Self::SendStorage>) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.flush(send)
    }

    fn graceful_close<'a>(&'a mut self, mut send: Storage<'a, Self::SendStorage>) -> Prepared<'a> {
        self.seal_close_notify(&mut send.0);
        let close_after = self.propagate_close(&mut send.0);
        let mut sender = Sender::new(self);
        sender.finish(send, 0, close_after)
    }
}

const _: () = assert!(
    core::mem::size_of::<Tls>() < crate::staging::MAX_TLS_RECORD,
    "inline Tls must not embed a record-sized staging array"
);
