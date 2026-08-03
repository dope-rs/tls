use std::{
    io::{self, Error, ErrorKind},
    marker::PhantomData,
    mem::{self, size_of},
};

use dope_net::wire::send::{Plain, Prepared, SendStorage, Storage, Vectored};
use dope_net::wire::{
    Lease, OpenRollback, Reclaim, RecvCredit, RuntimeLimits, Wire,
    buffered::{Buffer, Scratch, ScratchPool},
    reservation::ReservedOpen,
};
use dope_net::{Bytes, Retained};
use shin::client;
use shin::client::config::{
    self, ClientCertSource, ClientCertTemplate, ConfigTemplate, PreparedConfig,
};
use shin::crypto::ticket::TicketKeys;
use shin::server;
use shin::server::Shard;
use shin::server::config::{
    ClientAuth, ClientCertVerifier, Config, ConnectionConfig, EarlyDataGuard, NoClientAuth, NoGuard,
};

use crate::clock::WallClock;
use crate::error;
use crate::send::{SendBuffer, SendProtocol, Sender};
use crate::staging::{MAX_TLS_RECORD, TLS_STAGING_CAP};
use crate::state::buffer::Buffers;
use crate::state::direct::PlainChunks;
use crate::state::sessions::{Pool, PooledClient, PooledServer, Session};
use crate::state::{State, status::PeerClose};

mod connection;
mod egress;
mod open;
#[doc(hidden)]
pub mod recv;

use connection::ConnectionState;
use egress::Egress;
use open::Open;
use recv::Ingress;

mod sealed {
    pub trait Sealed {}
}

pub trait ServerPolicy: sealed::Sealed + 'static {
    type Guard: EarlyDataGuard + 'static;
    type Verifier: ClientCertVerifier + 'static;
}

pub struct Standard<G = NoGuard>(PhantomData<fn() -> G>);

impl<G> sealed::Sealed for Standard<G> {}

impl<G> ServerPolicy for Standard<G>
where
    G: EarlyDataGuard + 'static,
{
    type Guard = G;
    type Verifier = NoClientAuth;
}

pub struct Mutual<G, V>(PhantomData<fn() -> (G, V)>);

impl<G, V> sealed::Sealed for Mutual<G, V> {}

impl<G, V> ServerPolicy for Mutual<G, V>
where
    G: EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    type Guard = G;
    type Verifier = V;
}

type PolicyShard<P> = Shard<<P as ServerPolicy>::Guard, <P as ServerPolicy>::Verifier>;

pub struct ClientSetup {
    config: PreparedConfig,
    template: ConfigTemplate,
    cert: Option<ClientCertTemplate>,
}

/// One validated, connection-local TLS setup produced by a [`ClientSource`].
///
/// This is distinct from [`ClientSetup`], which owns the reusable endpoint
/// template. Keeping the dial value template-free avoids a redundant `Rc`
/// clone on every connection while making one-shot and reusable roles explicit.
#[doc(hidden)]
pub struct ClientDial {
    config: PreparedConfig,
    cert: Option<ClientCertTemplate>,
}

impl ClientSetup {
    pub fn new(config: config::Config) -> Result<Self, error::Error> {
        let config = config
            .try_into_prepared()
            .map_err(error::Error::InvalidConfig)?;
        let template = config.template();
        Ok(Self {
            config,
            template,
            cert: None,
        })
    }

    pub fn mutual(config: config::Config, cert: ClientCertSource) -> Result<Self, error::Error> {
        let mut setup = Self::new(config)?;
        setup.cert = Some(
            cert.try_into_template()
                .map_err(error::Error::InvalidConfig)?,
        );
        Ok(setup)
    }

    /// Clones the validated endpoint template for one dial and transfers the
    /// initial resumption ticket at most once.
    pub fn for_next_dial(&mut self) -> ClientDial {
        let config = mem::replace(&mut self.config, self.template.clone().without_resumption());
        ClientDial {
            config,
            cert: self.cert.clone(),
        }
    }
}

/// Supplies an already validated TLS setup for each outbound dial.
///
/// This source is deliberately total: resource backpressure is owned by the
/// runtime pools, while a source always supplies a setup after those resources
/// have been reserved. [`ClientSetup`]'s private fields make successful
/// construction the proof that static configuration is valid.
///
/// ```compile_fail
/// use dope_tls::tls::{ClientDial, ClientSource};
///
/// struct Exhaustible;
///
/// impl ClientSource for Exhaustible {
///     fn next(&mut self) -> Option<ClientDial> {
///         None
///     }
/// }
/// ```
pub trait ClientSource: 'static {
    fn next(&mut self) -> ClientDial;
}

pub struct StaticClientSource(ClientSetup);

impl ClientSource for StaticClientSource {
    fn next(&mut self) -> ClientDial {
        self.0.for_next_dial()
    }
}

pub struct Server<P = Standard>(PhantomData<fn() -> P>);

pub struct Client<S = StaticClientSource>(PhantomData<fn() -> S>);

pub struct ServerRuntime<'d, P: ServerPolicy> {
    shard: PolicyShard<P>,
    sessions: &'d Pool<server::Server<WallClock>>,
}

pub struct ClientRuntime<'d, S: ClientSource> {
    source: S,
    sessions: &'d Pool<client::Client<WallClock>>,
}

pub trait Role: sealed::Sealed + Sized + 'static {
    type Endpoint;
    type Runtime<'d>: 'd;
    type Session<'d>: Session + 'd;
    type Storage: 'static;

    #[doc(hidden)]
    fn storage(capacity: usize) -> io::Result<Self::Storage>;

    #[doc(hidden)]
    fn runtime<'d>(
        limits: RuntimeLimits,
        endpoint: Self::Endpoint,
        storage: &'d Self::Storage,
    ) -> io::Result<Self::Runtime<'d>>;

    #[doc(hidden)]
    fn open<'d>(
        runtime: &mut Self::Runtime<'d>,
        recv: ScratchPool,
        pending: ScratchPool,
    ) -> Result<Option<State<Self::Session<'d>>>, error::Error>;

    #[doc(hidden)]
    fn read_staged<'d>(
        state: &mut State<Self::Session<'d>>,
        runtime: &mut Self::Runtime<'d>,
        bytes: &[u8],
    ) -> (usize, Option<Bytes<Retained>>, bool, bool);

    #[doc(hidden)]
    fn read_direct<'a, 'd>(
        state: &mut State<Self::Session<'d>>,
        runtime: &mut Self::Runtime<'d>,
        bytes: &'a mut [u8],
    ) -> (PlainChunks<'a>, bool);
}

impl<P: ServerPolicy> sealed::Sealed for Server<P> {}

impl<P: ServerPolicy> Role for Server<P> {
    type Endpoint = PolicyShard<P>;
    type Runtime<'d> = ServerRuntime<'d, P>;
    type Session<'d> = PooledServer<'d>;
    type Storage = Pool<server::Server<WallClock>>;

    fn storage(capacity: usize) -> io::Result<Self::Storage> {
        Pool::with_capacity(capacity).map_err(|error| Error::new(ErrorKind::InvalidInput, error))
    }

    fn runtime<'d>(
        _: RuntimeLimits,
        shard: Self::Endpoint,
        sessions: &'d Self::Storage,
    ) -> io::Result<Self::Runtime<'d>> {
        Ok(ServerRuntime { shard, sessions })
    }

    fn open<'d>(
        runtime: &mut Self::Runtime<'d>,
        recv: ScratchPool,
        pending: ScratchPool,
    ) -> Result<Option<State<Self::Session<'d>>>, error::Error> {
        match State::<PooledServer<'d>>::with_pool(
            ConnectionConfig {
                transport_params: Vec::new(),
            },
            WallClock::System,
            Buffers::pooled(recv, pending),
            runtime.sessions,
        ) {
            Ok(state) => Ok(Some(state)),
            Err(error::Error::BufferUnavailable) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn read_staged<'d>(
        state: &mut State<Self::Session<'d>>,
        runtime: &mut Self::Runtime<'d>,
        bytes: &[u8],
    ) -> (usize, Option<Bytes<Retained>>, bool, bool) {
        state.read_staged_wire(bytes, &mut runtime.shard)
    }

    fn read_direct<'a, 'd>(
        state: &mut State<Self::Session<'d>>,
        runtime: &mut Self::Runtime<'d>,
        bytes: &'a mut [u8],
    ) -> (PlainChunks<'a>, bool) {
        state.read_tcp_in_place(bytes, &mut runtime.shard)
    }
}

impl<S: ClientSource> sealed::Sealed for Client<S> {}

impl<S: ClientSource> Role for Client<S> {
    type Endpoint = S;
    type Runtime<'d> = ClientRuntime<'d, S>;
    type Session<'d> = PooledClient<'d>;
    type Storage = Pool<client::Client<WallClock>>;

    fn storage(capacity: usize) -> io::Result<Self::Storage> {
        Pool::with_capacity(capacity).map_err(|error| Error::new(ErrorKind::InvalidInput, error))
    }

    fn runtime<'d>(
        _: RuntimeLimits,
        endpoint: Self::Endpoint,
        sessions: &'d Self::Storage,
    ) -> io::Result<Self::Runtime<'d>> {
        Ok(ClientRuntime {
            source: endpoint,
            sessions,
        })
    }

    fn open<'d>(
        runtime: &mut Self::Runtime<'d>,
        recv: ScratchPool,
        pending: ScratchPool,
    ) -> Result<Option<State<Self::Session<'d>>>, error::Error> {
        let Some(session) = runtime.sessions.reserve_client() else {
            return Ok(None);
        };
        let Some(pending_buffer) = pending.try_acquire() else {
            return Ok(None);
        };
        let ClientDial { config, cert } = runtime.source.next();
        State::<PooledClient<'d>>::with_reservation(
            session,
            config,
            cert,
            WallClock::System,
            Buffers::with_pending(recv, pending, pending_buffer),
        )
        .map(Some)
    }

    fn read_staged<'d>(
        state: &mut State<Self::Session<'d>>,
        _runtime: &mut Self::Runtime<'d>,
        bytes: &[u8],
    ) -> (usize, Option<Bytes<Retained>>, bool, bool) {
        state.read_staged_wire(bytes)
    }

    fn read_direct<'a, 'd>(
        state: &mut State<Self::Session<'d>>,
        _runtime: &mut Self::Runtime<'d>,
        bytes: &'a mut [u8],
    ) -> (PlainChunks<'a>, bool) {
        state.read_tcp_in_place(bytes)
    }
}

pub struct SessionStorage<R: Role = Server> {
    role: R::Storage,
}

impl<R: Role> SessionStorage<R> {
    pub fn try_with_capacity(capacity: usize) -> io::Result<Self> {
        Ok(Self {
            role: R::storage(capacity)?,
        })
    }
}

pub struct BoundEndpoint<'d, R: Role = Server> {
    endpoint: Endpoint<R>,
    storage: &'d SessionStorage<R>,
}

pub struct Endpoint<R: Role = Server> {
    role: R::Endpoint,
    retained_fragments: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferLayout {
    recv_slots: usize,
    pending_slots: usize,
    send_slots: usize,
    recv_capacity: usize,
    staging_capacity: usize,
    payload_bytes: usize,
}

impl BufferLayout {
    pub fn recv_slots(self) -> usize {
        self.recv_slots
    }

    pub fn pending_slots(self) -> usize {
        self.pending_slots
    }

    pub fn send_slots(self) -> usize {
        self.send_slots
    }

    pub fn recv_capacity(self) -> usize {
        self.recv_capacity
    }

    pub fn pending_capacity(self) -> usize {
        self.staging_capacity
    }

    pub fn send_capacity(self) -> usize {
        self.staging_capacity
    }

    /// Bytes reserved for pool payloads, excluding allocator and pool metadata.
    pub fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferUsage {
    recv_available: usize,
    pending_available: usize,
    send_available: usize,
}

impl BufferUsage {
    pub fn recv_available(self) -> usize {
        self.recv_available
    }

    pub fn pending_available(self) -> usize {
        self.pending_available
    }

    pub fn send_available(self) -> usize {
        self.send_available
    }
}

impl<R: Role> Endpoint<R> {
    pub fn bind<'d>(self, storage: &'d SessionStorage<R>) -> BoundEndpoint<'d, R> {
        BoundEndpoint {
            endpoint: self,
            storage,
        }
    }

    /// Sets the maximum number of fragmented plaintext records that may remain
    /// retained independently of active connections. With receive credit, the
    /// default is one retained fragment per connection; otherwise it preserves
    /// the complete runtime receive limit. A lower explicit budget bounds TLS
    /// pool memory more tightly, but can close a connection if every fragment
    /// slot is retained when another fragmented record completes.
    pub fn with_retained_fragment_budget(mut self, records: usize) -> Self {
        self.retained_fragments = Some(records);
        self
    }

    pub fn buffer_layout(&self, limits: RuntimeLimits) -> io::Result<BufferLayout> {
        let retained_fragments = self.retained_fragments.unwrap_or_else(|| {
            if limits.recv_credit() {
                // One credited cursor and one newly staged tail are the only
                // two receive scratches a connection can own at a transform
                // boundary. The cursor pauses that connection before another
                // transform, making this one retained slot per connection a
                // complete bound rather than an admission heuristic.
                limits.max_connections()
            } else {
                limits.max_retained_recv_chunks()
            }
        });
        let retained_fragments = retained_fragments.min(limits.max_retained_recv_chunks());
        let recv_slots = limits
            .max_connections()
            .checked_add(retained_fragments)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "TLS receive slot overflow"))?;
        let pending_slots = limits.max_connections();
        let send_slots = limits.max_connections();
        let payload_bytes = recv_slots
            .checked_mul(MAX_TLS_RECORD)
            .and_then(|bytes| {
                pending_slots
                    .checked_mul(TLS_STAGING_CAP)
                    .and_then(|pending| bytes.checked_add(pending))
            })
            .and_then(|bytes| {
                send_slots
                    .checked_mul(TLS_STAGING_CAP)
                    .and_then(|send| bytes.checked_add(send))
            })
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "TLS buffer size overflow"))?;
        Ok(BufferLayout {
            recv_slots,
            pending_slots,
            send_slots,
            recv_capacity: MAX_TLS_RECORD,
            staging_capacity: TLS_STAGING_CAP,
            payload_bytes,
        })
    }
}

impl Endpoint<Server> {
    pub fn server(config: Config) -> Result<Self, error::Error> {
        config.validate().map_err(error::Error::Handshake)?;
        Ok(Self {
            role: Shard::new(config),
            retained_fragments: None,
        })
    }
}

impl<G> Endpoint<Server<Standard<G>>>
where
    G: EarlyDataGuard + 'static,
{
    pub fn server_with_early_data_guard(config: Config, guard: G) -> Result<Self, error::Error> {
        config.validate().map_err(error::Error::Handshake)?;
        Ok(Self {
            role: Shard::with_early_data_guard(config, guard),
            retained_fragments: None,
        })
    }
}

impl<V> Endpoint<Server<Mutual<NoGuard, V>>>
where
    V: ClientCertVerifier + 'static,
{
    pub fn server_mutual(
        config: Config,
        auth: ClientAuth,
        verifier: V,
    ) -> Result<Self, error::Error> {
        config.validate().map_err(error::Error::Handshake)?;
        Ok(Self {
            role: Shard::with_client_auth(config, auth, verifier),
            retained_fragments: None,
        })
    }
}

impl<G, V> Endpoint<Server<Mutual<G, V>>>
where
    G: EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    pub fn server_mutual_with_early_data_guard(
        config: Config,
        guard: G,
        auth: ClientAuth,
        verifier: V,
    ) -> Result<Self, error::Error> {
        config.validate().map_err(error::Error::Handshake)?;
        Ok(Self {
            role: Shard::with_early_data_guard_and_client_auth(config, guard, auth, verifier),
            retained_fragments: None,
        })
    }
}

impl Endpoint<Client<StaticClientSource>> {
    pub fn client(config: config::Config) -> Result<Self, error::Error> {
        Ok(Self {
            role: StaticClientSource(ClientSetup::new(config)?),
            retained_fragments: None,
        })
    }

    pub fn client_mutual(
        config: config::Config,
        cert: ClientCertSource,
    ) -> Result<Self, error::Error> {
        Ok(Self {
            role: StaticClientSource(ClientSetup::mutual(config, cert)?),
            retained_fragments: None,
        })
    }
}

impl<S: ClientSource> Endpoint<Client<S>> {
    pub fn client_source(source: S) -> Self {
        Self {
            role: source,
            retained_fragments: None,
        }
    }
}

struct RuntimeBuffers {
    recv: ScratchPool,
    pending: ScratchPool,
    send: ScratchPool,
}

pub struct Runtime<'d, R: Role> {
    retry: Option<(TlsConnection<'d, R>, SendState)>,
    buffers: RuntimeBuffers,
    role: R::Runtime<'d>,
}

impl<R: Role> Runtime<'_, R> {
    #[doc(hidden)]
    pub fn buffer_usage(&self) -> BufferUsage {
        BufferUsage {
            recv_available: self.buffers.recv.available(),
            pending_available: self.buffers.pending.available(),
            send_available: self.buffers.send.available(),
        }
    }
}

impl<P: ServerPolicy> Runtime<'_, Server<P>> {
    pub fn replace_ticket_keys(&mut self, keys: Option<TicketKeys>) {
        self.role.shard.replace_ticket_keys(keys);
    }
}

impl<'d, R: Role> OpenRollback<TlsConnection<'d, R>, SendState> for Runtime<'d, R> {
    fn rollback_open(&mut self, open: (TlsConnection<'d, R>, SendState)) {
        let displaced = self.retry.replace(open);
        debug_assert!(displaced.is_none());
        mem::forget(displaced);
    }
}

pub struct Tls<R: Role = Server>(PhantomData<fn() -> R>);

#[doc(hidden)]
pub struct TlsConnection<'d, R: Role = Server> {
    state: ConnectionState<R::Session<'d>>,
    send_inflight: bool,
}

pub struct SendState {
    pool: ScratchPool,
    buffer: Option<Buffer<Scratch>>,
}

impl SendState {
    fn new(pool: ScratchPool) -> Self {
        Self { pool, buffer: None }
    }
}

impl SendStorage for SendState {
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_ref().map_or(&[], Buffer::as_slice)
    }
}

impl SendBuffer for SendState {
    fn buffer_mut(&mut self) -> Option<&mut Buffer<Scratch>> {
        self.buffer.as_mut()
    }

    fn try_buffer(&mut self) -> Option<&mut Buffer<Scratch>> {
        if self.buffer.is_none() {
            self.buffer = self.pool.try_acquire();
        }
        self.buffer.as_mut()
    }

    fn release_if_empty(&mut self) {
        if self.buffer.as_ref().is_some_and(Buffer::is_empty) {
            self.buffer = None;
        }
    }
}

impl<R: Role> TlsConnection<'_, R> {
    pub fn peer_close(&self) -> PeerClose {
        self.state.tls.peer_close()
    }
}

impl<R: Role> SendProtocol for TlsConnection<'_, R> {
    type Storage = SendState;

    fn needs_buffer(&self) -> bool {
        !self.state.tls.pending_send_slice().is_empty()
    }

    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        if plain.is_empty() {
            Egress::new(self).drain(egress);
            return 0;
        }
        Egress::new(self).encrypt(egress, plain)
    }

    fn encrypt_vectored(&mut self, egress: &mut Buffer<Scratch>, vectored: &Vectored<'_>) -> usize {
        if vectored.bytes() == 0 {
            Egress::new(self).drain(egress);
            return 0;
        }
        Egress::new(self).encrypt_vectored(egress, vectored)
    }

    fn propagate_close(&mut self, _egress: &mut Buffer<Scratch>) -> bool {
        Egress::new(self).propagate_close()
    }

    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>) {
        if egress.spare_capacity() == 0 {
            return;
        }
        Egress::new(self).drain(egress);
    }

    fn send_inflight(&mut self) -> &mut bool {
        &mut self.send_inflight
    }
}

impl<R: Role> Wire for Tls<R> {
    type Connection<'d> = TlsConnection<'d, R>;
    type ConnectionStorage = SessionStorage<R>;
    type InitConfig<'d> = BoundEndpoint<'d, R>;
    type RuntimeContext<'d> = Runtime<'d, R>;
    type Open<'a, 'd>
        = ReservedOpen<'a, Self::Connection<'d>, Self::SendStorage, Self::RuntimeContext<'d>>
    where
        'd: 'a;
    type OpenError = error::Error;
    type Recv<'a> = Bytes<Retained>;
    type RecvBatch<'a> = recv::TlsRecvBatch<'a>;
    type RetainedRecv<'d> = recv::TlsRetained<'d>;
    type SendStorage = SendState;

    const RECLAIM: Reclaim = Reclaim::OnSubmit;
    const RECV_CREDIT: bool = true;

    fn connection_storage(capacity: usize) -> io::Result<Self::ConnectionStorage> {
        SessionStorage::try_with_capacity(capacity)
    }

    fn holds_plain<'d>(_: &Self::Connection<'d>, send: &Self::SendStorage) -> bool {
        !send.as_slice().is_empty()
    }

    fn runtime_context<'d>(
        limits: RuntimeLimits,
        config: Self::InitConfig<'d>,
    ) -> io::Result<Self::RuntimeContext<'d>>
    where
        Self: 'd,
    {
        let BoundEndpoint { endpoint, storage } = config;
        let config = endpoint;
        let layout = config.buffer_layout(limits)?;
        let role = R::runtime(limits, config.role, &storage.role)?;
        let recv = ScratchPool::try_new(layout.recv_slots(), layout.recv_capacity())
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        let pending = ScratchPool::try_new(layout.pending_slots(), layout.pending_capacity())
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        let send = ScratchPool::try_new(layout.send_slots(), layout.send_capacity())
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        Ok(Runtime {
            retry: None,
            buffers: RuntimeBuffers {
                recv,
                pending,
                send,
            },
            role,
        })
    }

    fn prepare_open<'a, 'd>(
        runtime: &'a mut Self::RuntimeContext<'d>,
    ) -> Result<Option<Self::Open<'a, 'd>>, error::Error>
    where
        'd: 'a,
    {
        let (tls, send) = match runtime.retry.take() {
            Some(value) => value,
            None => match Open::new(runtime).try_take()? {
                Some(value) => value,
                None => return Ok(None),
            },
        };
        Ok(Some(ReservedOpen::new(runtime, tls, send)))
    }

    fn process_recv<'a, 'd>(
        wire: &mut Self::Connection<'d>,
        runtime: &mut Self::RuntimeContext<'d>,
        bytes: &'a mut [u8],
    ) -> Self::RecvBatch<'a> {
        Ingress::<R>::new(&mut wire.state, &mut runtime.role)
            .read(bytes)
            .into_batch()
    }

    fn process_retained_recv<'a, 'd>(
        wire: &mut Self::Connection<'d>,
        runtime: &mut Self::RuntimeContext<'d>,
        mut bytes: Lease<'a>,
    ) -> Option<Self::RetainedRecv<'a>> {
        let retained = Ingress::<R>::new(&mut wire.state, &mut runtime.role)
            .read(bytes.as_mut_slice())
            .retain();
        retained.into_cursor(bytes)
    }

    fn bind_recv_credit<'d>(
        recv: &mut Self::RetainedRecv<'d>,
        credit: RecvCredit<'d>,
    ) -> Result<(), RecvCredit<'d>> {
        recv.bind_recv_credit(credit)
    }

    fn recv_eof<'d>(wire: &mut Self::Connection<'d>) {
        let _ = wire.state.tls.peer_eof();
        wire.state.close = true;
    }

    fn prepare_send<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
        plain: Plain<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.prepare(send, plain)
    }

    fn prepare_send_vectored<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
        vectored: Vectored<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.prepare_vectored(send, vectored)
    }

    fn submit_failed<'d>(wire: &mut Self::Connection<'d>) {
        wire.send_inflight = false;
    }

    fn after_send<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
        sent: dope_net::wire::send::Sent,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.after_send(send, sent)
    }

    fn flush_pending<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.flush(send)
    }

    fn graceful_close<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        mut send: Storage<'a, Self::SendStorage>,
    ) -> Prepared<'a> {
        let Some(buffer) = send.try_buffer() else {
            return send.empty(0).close_after();
        };
        let mut egress = Egress::new(wire);
        egress.seal_close_notify(buffer);
        let close_after = egress.propagate_close();
        let mut sender = Sender::new(wire);
        sender.finish(send, 0, close_after)
    }
}

const _: () = assert!(size_of::<TlsConnection<'static>>() < MAX_TLS_RECORD);
const _: () = assert!(size_of::<Server>() == 0);
const _: () = assert!(size_of::<Client>() == 0);
const _: () = assert!(
    size_of::<TlsConnection<'static, Client>>() == size_of::<TlsConnection<'static, Server>>()
);
