use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream};
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};
use std::task::Poll;
use std::time::{Duration, Instant};

use dope::net::wire::{RuntimeLimits, Wire};
use dope::runtime::executor::{self, Application};
use dope_fiber::abi::PollFn;
use dope_fiber::extensions::AppSessionExt;
use dope_tls::state::api::capabilities::{Status, Write};
use dope_tls::state::api::reads::{Client, Server};
use dope_tls::{
    Clock, Error,
    state::{
        State,
        sessions::{self, clients, servers},
    },
    tls::{self, ClientPlan, endpoints, roles},
};
use ring::rand::{SecureRandom, SystemRandom};
use shin::crypto::sig::SigningKey;

static RUNTIME_FIXTURE: Mutex<()> = Mutex::new(());

const TEST_STATE_CAPACITY: usize = 16;
const TEST_MAX_RECV_LEN: usize = 64 * 1024;
type ClientTls = tls::Tls<roles::Client>;
type ServerTls = tls::Tls;

fn client_state(plan: ClientPlan) -> Result<State<'static, clients::Pooled<'static>>, Error> {
    let storage = Box::leak(Box::new(
        endpoints::SessionStorage::<roles::Client>::try_with_capacity(TEST_STATE_CAPACITY)?,
    ));
    let endpoint = endpoints::Configuration::from_plan(plan);
    let mut runtime = ClientTls::runtime_context::<0>(state_limits(), endpoint.bind(storage))?;
    runtime.open_state()?.ok_or(Error::BufferUnavailable)
}

fn state_limits() -> RuntimeLimits {
    RuntimeLimits::new(TEST_STATE_CAPACITY, TEST_STATE_CAPACITY, TEST_MAX_RECV_LEN)
}

pub(crate) fn runtime_fixture() -> MutexGuard<'static, ()> {
    RUNTIME_FIXTURE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) type ServerState<
    G = shin::server::config::NoGuard,
    V = shin::server::config::NoClientAuth,
> = State<'static, servers::Pooled<'static, 0, G, V>>;

pub(crate) struct ClientState {
    state: State<'static, clients::Pooled<'static>>,
    incoming: VecDeque<Vec<u8>>,
}

impl ClientState {
    pub(crate) fn new(config: shin::client::config::Config) -> Result<Self, Error> {
        client_state(ClientPlan::new(config)?).map(Self::from)
    }

    pub(crate) fn with_clock(
        config: shin::client::config::Config,
        clock: Clock,
    ) -> Result<Self, Error> {
        client_state(ClientPlan::new(config)?.with_clock(clock)).map(Self::from)
    }

    pub(crate) fn mutual(
        config: shin::client::config::Config,
        identity: shin::client::config::Identity,
    ) -> Result<Self, Error> {
        client_state(ClientPlan::mutual(config, identity)?).map(Self::from)
    }

    pub(crate) fn read_tcp(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let incoming = &mut self.incoming;
        self.state
            .read_tcp(bytes, |chunk| incoming.push_back(chunk.to_vec()))
    }

    pub(crate) fn try_read_tcp(&mut self, bytes: &[u8]) -> bool {
        let incoming = &mut self.incoming;
        self.state
            .try_read_tcp(bytes, |chunk| incoming.push_back(chunk.to_vec()))
    }

    pub(crate) fn read_tcp_in_place<'a>(
        &mut self,
        bytes: &'a mut [u8],
    ) -> dope_tls::state::direct::WireRead<'a> {
        Client::read_tcp_in_place(&mut self.state, bytes)
    }

    pub(crate) fn read_staged_wire(
        &mut self,
        bytes: &[u8],
    ) -> dope_tls::state::staged::WireRead<'_> {
        Client::read_staged_wire(&mut self.state, bytes)
    }

    pub(crate) fn pull_send(&mut self) -> Vec<u8> {
        take_send(&mut self.state)
    }

    pub(crate) fn pull_app(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }

    pub(crate) fn pending_send_slice(&self) -> &[u8] {
        Write::pending_send_slice(&self.state)
    }

    pub(crate) fn consume_pending_send(&mut self, count: usize) -> Result<(), Error> {
        Write::consume_pending_send(&mut self.state, count)
    }

    pub(crate) fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, Error> {
        Write::write_app(&mut self.state, plaintext)
    }

    pub(crate) fn send_close_notify(&mut self) -> Result<(), Error> {
        Write::send_close_notify(&mut self.state)
    }

    pub(crate) fn peer_close(&self) -> dope_tls::state::status::PeerClose {
        Status::peer_close(&self.state)
    }

    pub(crate) fn peer_eof(&mut self) -> Result<(), Error> {
        Status::peer_eof(&mut self.state)
    }

    pub(crate) fn is_handshaking(&self) -> bool {
        Status::is_handshaking(&self.state)
    }

    pub(crate) fn is_established(&self) -> bool {
        Status::is_established(&self.state)
    }

    pub(crate) fn is_closed(&self) -> bool {
        Status::is_closed(&self.state)
    }

    pub(crate) fn phase(&self) -> dope_tls::state::status::Phase {
        Status::phase(&self.state)
    }
}

impl From<State<'static, clients::Pooled<'static>>> for ClientState {
    fn from(state: State<'static, clients::Pooled<'static>>) -> Self {
        Self {
            state,
            incoming: VecDeque::new(),
        }
    }
}

impl Deref for ClientState {
    type Target = State<'static, clients::Pooled<'static>>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for ClientState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

pub(crate) struct TestServer<
    G = shin::server::config::NoGuard,
    V = shin::server::config::NoClientAuth,
> where
    G: shin::server::config::EarlyDataGuard + 'static,
    V: shin::server::config::ClientCertVerifier + 'static,
{
    state: ServerState<G, V>,
    incoming: VecDeque<Vec<u8>>,
}

impl<G, V> TestServer<G, V>
where
    G: shin::server::config::EarlyDataGuard + 'static,
    V: shin::server::config::ClientCertVerifier + 'static,
{
    pub(crate) fn new(state: ServerState<G, V>) -> Self {
        Self {
            state,
            incoming: VecDeque::new(),
        }
    }

    pub(crate) fn read_tcp(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let incoming = &mut self.incoming;
        self.state.read_tcp(bytes, |chunk| {
            incoming.push_back(chunk.to_vec());
        })
    }

    pub(crate) fn read_tcp_in_place<'a>(
        &mut self,
        bytes: &'a mut [u8],
    ) -> dope_tls::state::direct::WireRead<'a> {
        self.state.read_tcp_in_place(bytes)
    }

    pub(crate) fn read_staged_wire(
        &mut self,
        bytes: &[u8],
    ) -> dope_tls::state::staged::WireRead<'_> {
        self.state.read_staged_wire(bytes)
    }

    pub(crate) fn staged_recv(&self) -> &[u8] {
        self.state.staged_recv()
    }

    pub(crate) fn pull_send(&mut self) -> Vec<u8> {
        take_send(&mut self.state)
    }

    pub(crate) fn pull_app(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }

    pub(crate) fn pending_send_slice(&self) -> &[u8] {
        Write::pending_send_slice(&self.state)
    }

    pub(crate) fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, Error> {
        Write::write_app(&mut self.state, plaintext)
    }

    pub(crate) fn send_key_update(
        &mut self,
        request: shin::wire::handshake::KeyUpdateRequest,
    ) -> Result<(), Error> {
        Write::send_key_update(&mut self.state, request)
    }

    pub(crate) fn send_close_notify(&mut self) -> Result<(), Error> {
        Write::send_close_notify(&mut self.state)
    }

    pub(crate) fn send_fatal_alert(
        &mut self,
        description: shin::wire::alert::Description,
    ) -> Result<(), Error> {
        Write::send_fatal_alert(&mut self.state, description)
    }

    pub(crate) fn has_staged_recv(&self) -> bool {
        Status::has_staged_recv(&self.state)
    }

    pub(crate) fn peer_close(&self) -> dope_tls::state::status::PeerClose {
        Status::peer_close(&self.state)
    }

    pub(crate) fn peer_eof(&mut self) -> Result<(), Error> {
        Status::peer_eof(&mut self.state)
    }

    pub(crate) fn is_handshaking(&self) -> bool {
        Status::is_handshaking(&self.state)
    }

    pub(crate) fn is_established(&self) -> bool {
        Status::is_established(&self.state)
    }

    pub(crate) fn is_closed(&self) -> bool {
        Status::is_closed(&self.state)
    }
}

impl<G, V> Deref for TestServer<G, V>
where
    G: shin::server::config::EarlyDataGuard + 'static,
    V: shin::server::config::ClientCertVerifier + 'static,
{
    type Target = ServerState<G, V>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<G, V> DerefMut for TestServer<G, V>
where
    G: shin::server::config::EarlyDataGuard + 'static,
    V: shin::server::config::ClientCertVerifier + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

pub(crate) fn wait_for_addr(addr: SocketAddr) -> TcpStream {
    for _ in 0..200 {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("could not connect to {addr}");
}

pub(crate) fn drive_until<'d, D: Application<'d>, F: FnMut() -> bool + 'static>(
    app: &mut executor::session::Application<'_, 'd, D>,
    mut done: F,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let fiber = PollFn::new(move |cx| {
        if done() || Instant::now() >= deadline {
            Poll::Ready(())
        } else {
            cx.waker().wake();
            Poll::Pending
        }
    });
    app.block_on(fiber).unwrap();
}

pub(crate) fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    SigningKey::from_seed(&seed).unwrap()
}

pub(crate) fn raw_server(signing_key: SigningKey) -> TestServer {
    let config = shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    };
    let shard = shin::server::Shard::new(config).expect("valid server shard");
    TestServer::new(server_state(shard).expect("valid server buffer layout"))
}

pub(crate) fn server_state(shard: shin::server::Shard) -> Result<ServerState, Error> {
    let storage = Box::leak(Box::new(
        endpoints::SessionStorage::<roles::Server>::try_with_capacity(TEST_STATE_CAPACITY)?,
    ));
    let mut runtime =
        ServerTls::runtime_context::<0>(state_limits(), storage.bind_endpoint(shard))?;
    runtime.open_state()?.ok_or(Error::BufferUnavailable)
}

pub(crate) fn mutual_server_state<G, V>(
    shard: shin::server::Shard<G, shin::server::config::ClientAuthVerifier<V>>,
) -> Result<ServerState<G, shin::server::config::ClientAuthVerifier<V>>, Error>
where
    G: shin::server::config::EarlyDataGuard + 'static,
    V: shin::server::config::ClientCertVerifier + 'static,
{
    type Role<G, V> = roles::Server<roles::Mutual<G, V>>;
    let storage: &'static endpoints::SessionStorage<Role<G, V>> = Box::leak(Box::new(
        endpoints::SessionStorage::try_with_capacity(TEST_STATE_CAPACITY)?,
    ));
    let mut runtime =
        tls::Tls::<Role<G, V>>::runtime_context::<0>(state_limits(), storage.bind_endpoint(shard))?;
    runtime.open_state()?.ok_or(Error::BufferUnavailable)
}

pub(crate) fn raw_client(server_pubkey: [u8; 32]) -> ClientState {
    ClientState::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    })
    .unwrap()
}

pub(crate) fn raw_pair() -> (ClientState, TestServer) {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    (raw_client(server_pubkey), raw_server(signing))
}

pub(crate) fn pump<G, V>(client: &mut ClientState, server: &mut TestServer<G, V>)
where
    G: shin::server::config::EarlyDataGuard + 'static,
    V: shin::server::config::ClientCertVerifier + 'static,
{
    for _ in 0..16 {
        let from_client = client.pull_send();
        let from_server = server.pull_send();
        let progressed = !from_client.is_empty() || !from_server.is_empty();
        if !from_client.is_empty() {
            let _ = server.read_tcp(&from_client);
        }
        if !from_server.is_empty() {
            let _ = client.read_tcp(&from_server);
        }
        if !progressed {
            break;
        }
    }
}

pub(crate) fn established_pair() -> (ClientState, TestServer) {
    let (mut client, mut server) = raw_pair();
    pump(&mut client, &mut server);
    assert!(client.is_established() && server.is_established());
    (client, server)
}

fn take_send<S: sessions::Peer>(state: &mut State<'_, S>) -> Vec<u8> {
    let pending = state.pending_send_slice().to_vec();
    state.consume_pending_send(pending.len()).unwrap();
    pending
}
