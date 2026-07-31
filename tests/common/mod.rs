#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream};
use std::ops::{Deref, DerefMut};
use std::task::Poll;
use std::time::{Duration, Instant};

use dope::runtime::dispatcher::Dispatcher;
use dope::runtime::executor::AppSession;
use dope_fiber::abi::pollfn::PollFn;
use dope_fiber::extensions::AppSessionExt as _;
use dope_net::{Bytes, Retained};
use dope_tls::{
    clock::WallClock,
    state::{
        State,
        sessions::{Client, Server, Session},
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use shin::crypto::sig::SigningKey;

pub(crate) type ServerState = State<Server>;

pub(crate) trait AppQueue {
    fn pull_app(&mut self) -> Option<Vec<u8>>;
}

pub(crate) struct ClientState {
    state: State<Client>,
    incoming: VecDeque<Vec<u8>>,
}

impl AppQueue for ClientState {
    fn pull_app(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }
}

impl ClientState {
    pub(crate) fn new(
        config: shin::client::config::Config,
    ) -> Result<Self, dope_tls::error::Error> {
        State::<Client>::new(config).map(Self::from)
    }

    pub(crate) fn with_clock(
        config: shin::client::config::Config,
        clock: WallClock,
    ) -> Result<Self, dope_tls::error::Error> {
        State::<Client>::with_clock(config, clock).map(Self::from)
    }

    pub(crate) fn with(
        config: shin::client::config::Config,
        clock: WallClock,
        configure: impl FnOnce(&mut shin::client::Client<WallClock>),
    ) -> Result<Self, dope_tls::error::Error> {
        State::with(config, clock, configure).map(Self::from)
    }

    pub(crate) fn mutual(
        config: shin::client::config::Config,
        cert: shin::client::config::ClientCertSource,
    ) -> Result<Self, dope_tls::error::Error> {
        State::mutual(config, cert).map(Self::from)
    }

    pub(crate) fn read_tcp(&mut self, bytes: &[u8]) -> Result<(), dope_tls::error::Error> {
        let incoming = &mut self.incoming;
        self.state
            .read_tcp(bytes, |chunk| incoming.push_back(chunk.to_vec()))
    }

    pub(crate) fn try_read_tcp(&mut self, bytes: &[u8]) -> bool {
        let incoming = &mut self.incoming;
        self.state
            .try_read_tcp(bytes, |chunk| incoming.push_back(chunk.to_vec()))
    }

    pub(crate) fn pull_send(&mut self) -> Vec<u8> {
        take_send(&mut self.state)
    }

    pub(crate) fn pull_app(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }
}

impl From<State<Client>> for ClientState {
    fn from(state: State<Client>) -> Self {
        Self {
            state,
            incoming: VecDeque::new(),
        }
    }
}

impl Deref for ClientState {
    type Target = State<Client>;

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
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    state: ServerState,
    shard: shin::server::Shard<G, V>,
    incoming: VecDeque<Vec<u8>>,
}

impl<G, V> TestServer<G, V>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    pub(crate) fn new(state: ServerState, shard: shin::server::Shard<G, V>) -> Self {
        Self {
            state,
            shard,
            incoming: VecDeque::new(),
        }
    }

    pub(crate) fn read_tcp(&mut self, bytes: &[u8]) -> Result<(), dope_tls::error::Error> {
        let incoming = &mut self.incoming;
        self.state.read_tcp(bytes, &mut self.shard, |chunk| {
            incoming.push_back(chunk.to_vec());
        })
    }

    pub(crate) fn read_tcp_in_place<'a>(
        &mut self,
        bytes: &'a mut [u8],
    ) -> (dope_tls::state::direct::PlainChunks<'a>, bool) {
        self.state.read_tcp_in_place(bytes, &mut self.shard)
    }

    pub(crate) fn read_staged_wire(
        &mut self,
        bytes: &[u8],
    ) -> (usize, Option<Bytes<Retained>>, bool, bool) {
        self.state.read_staged_wire(bytes, &mut self.shard)
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
}

impl<G, V> AppQueue for TestServer<G, V>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    fn pull_app(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }
}

impl<G, V> Deref for TestServer<G, V>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    type Target = ServerState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<G, V> DerefMut for TestServer<G, V>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
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

pub(crate) fn drive_until<'d, S, D: Dispatcher<'d>, F: FnMut() -> bool + 'static>(
    app: &mut AppSession<'_, '_, 'd, S, D>,
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
    config.validate().unwrap();
    TestServer::new(
        ServerState::new(shin::server::config::ConnectionConfig {
            transport_params: Vec::new(),
        })
        .expect("valid server buffer layout"),
        shin::server::Shard::new(config),
    )
}

pub(crate) fn raw_client(server_pubkey: [u8; 32]) -> ClientState {
    ClientState::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap()
}

pub(crate) fn raw_pair() -> (ClientState, TestServer) {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    (raw_client(server_pubkey), raw_server(signing))
}

pub(crate) fn raw_pair_with_suites(
    suites: &[shin::wire::record::CipherSuite],
) -> (ClientState, TestServer) {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    let client = ClientState::with(
        shin::client::config::Config {
            verifier: shin::client::config::Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        WallClock::System,
        |c| c.set_cipher_suites(suites),
    )
    .unwrap();
    (client, raw_server(signing))
}

pub(crate) fn pump<G, V>(client: &mut ClientState, server: &mut TestServer<G, V>)
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
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

fn take_send<S: Session>(state: &mut State<S>) -> Vec<u8> {
    let pending = state.pending_send_slice().to_vec();
    state.consume_pending_send(pending.len()).unwrap();
    pending
}
