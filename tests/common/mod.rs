#![allow(dead_code)]

use std::net::{SocketAddr, TcpStream};
use std::ops::{Deref, DerefMut};
use std::task::Poll;
use std::time::{Duration, Instant};

use dope::runtime::{AppSession, Dispatcher};
use dope_fiber::AppSessionExt as _;
use dope_tls::{clock::WallClock, state::State};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

pub(crate) struct TestServer<G = shin::server::NoGuard, V = shin::server::NoClientAuth>
where
    G: shin::server::EarlyDataGuard,
    V: shin::server::ClientCertVerifier,
{
    state: State,
    shard: shin::server::Shard<G, V>,
}

impl<G, V> TestServer<G, V>
where
    G: shin::server::EarlyDataGuard,
    V: shin::server::ClientCertVerifier,
{
    pub(crate) fn new(state: State, shard: shin::server::Shard<G, V>) -> Self {
        Self { state, shard }
    }

    pub(crate) fn read_tcp(&mut self, bytes: &[u8]) -> Result<(), dope_tls::error::Error> {
        self.state.read_server_tcp(bytes, &mut self.shard)
    }
}

impl<G, V> Deref for TestServer<G, V>
where
    G: shin::server::EarlyDataGuard,
    V: shin::server::ClientCertVerifier,
{
    type Target = State;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<G, V> DerefMut for TestServer<G, V>
where
    G: shin::server::EarlyDataGuard,
    V: shin::server::ClientCertVerifier,
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
    let fiber = dope_fiber::poll_fn(move |cx| {
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
    let config = shin::server::Config {
        source: shin::server::CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    };
    config.validate().unwrap();
    TestServer::new(
        State::new_server(shin::server::ConnectionConfig {
            transport_params: Vec::new(),
        })
        .expect("valid server buffer layout"),
        shin::server::Shard::new(config),
    )
}

pub(crate) fn raw_client(server_pubkey: [u8; 32]) -> State {
    State::new_client(shin::client::Config {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap()
}

pub(crate) fn raw_pair() -> (State, TestServer) {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    (raw_client(server_pubkey), raw_server(signing))
}

pub(crate) fn raw_pair_with_suites(suites: &[shin::record::CipherSuite]) -> (State, TestServer) {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    let client = State::new_client_with(
        shin::client::Config {
            verifier: shin::client::Verifier::RawPublicKey {
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

pub(crate) fn pump<G, V>(client: &mut State, server: &mut TestServer<G, V>)
where
    G: shin::server::EarlyDataGuard,
    V: shin::server::ClientCertVerifier,
{
    for _ in 0..16 {
        let from_client = client.pull_send();
        let from_server = server.pull_send();
        let progressed = !from_client.is_empty() || !from_server.is_empty();
        if !from_client.is_empty() {
            let _ = server.read_tcp(&from_client);
        }
        if !from_server.is_empty() {
            let _ = client.read_client_tcp(&from_server);
        }
        if !progressed {
            break;
        }
    }
}

pub(crate) fn established_pair() -> (State, TestServer) {
    let (mut client, mut server) = raw_pair();
    pump(&mut client, &mut server);
    assert!(client.is_established() && server.is_established());
    (client, server)
}
