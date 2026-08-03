#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread::JoinHandle;
use std::time::Duration;

use dope::runtime::executor::Executor;
use dope::runtime::profile::Balanced;
use dope_fiber::extensions::AppSessionExt;
use dope_fiber::net::connector::{Connector, ConnectorPort};
use dope_net::tcp::Tcp;
use dope_tls::tls::{Client, Endpoint, Tls};
use dope_tls::{ClientAuth, ClientCertSource, ClientCertVerifier, ClientIdentity};
use shin::crypto::sig::SigningKey;

mod common;

const KEY_SEED: [u8; 32] = [0x5a; 32];
const PING: &[u8] = b"ping";
const PONG: &[u8] = b"pong";

const CONNECTIONS: usize = 1;
type ClientTls = Tls<Client>;
type ClientConnector<'scope, 'd> = Connector<'scope, 'd, 0, Tcp, ClientTls>;

#[pin_project::pin_project]
#[derive(dope_gen::Dispatcher)]
struct App<'d, 'scope> {
    #[pin]
    #[manifold]
    connector: ClientConnector<'scope, 'd>,
}

fn client_config(server_pubkey: [u8; 32]) -> shin::client::config::Config {
    shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    }
}

struct PinnedVerifier {
    expected_spki: Vec<u8>,
}

impl ClientCertVerifier for PinnedVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        identity.spki_der == self.expected_spki
    }
}

fn client_spki(pubkey: [u8; 32]) -> Vec<u8> {
    shin::identity::spki::SubjectPublicKey::Ed25519(pubkey)
        .encode()
        .unwrap()
}

fn exchange_tls_connection<G, V>(
    mut stream: std::net::TcpStream,
    mut server: common::TestServer<G, V>,
) -> usize
where
    G: shin::server::config::EarlyDataGuard,
    V: ClientCertVerifier,
{
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    let mut input = [0; 16 * 1024];
    let mut received = Vec::new();

    for _ in 0..64 {
        let outgoing = server.pull_send();
        if !outgoing.is_empty() {
            stream.write_all(&outgoing).expect("write TLS flight");
        }
        while let Some(chunk) = server.pull_app() {
            received.extend_from_slice(&chunk);
        }
        if received == PING {
            server.write_app(PONG).expect("seal reply");
            let reply = server.pull_send();
            stream.write_all(&reply).expect("write TLS reply");
            return received.len();
        }

        let read = stream.read(&mut input).expect("read TLS bytes");
        assert_ne!(read, 0, "client closed before application round-trip");
        server
            .read_tcp(&input[..read])
            .expect("process client TLS bytes");
    }
    panic!("TLS application round-trip did not complete");
}

fn serve_tls_connection(stream: std::net::TcpStream) -> usize {
    let signing_key = SigningKey::from_seed(&KEY_SEED).expect("server signing key");
    exchange_tls_connection(stream, common::raw_server(signing_key))
}

fn serve_mutual_tls_connection(stream: std::net::TcpStream, client_pubkey: [u8; 32]) -> usize {
    let signing_key = SigningKey::from_seed(&KEY_SEED).expect("server signing key");
    let config = shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    };
    config.validate().expect("server config");
    let server = common::TestServer::new(
        common::ServerState::new(shin::server::config::ConnectionConfig {
            transport_params: Vec::new(),
        })
        .expect("server state"),
        shin::server::Shard::with_client_auth(
            config,
            ClientAuth::Required,
            PinnedVerifier {
                expected_spki: client_spki(client_pubkey),
            },
        ),
    );
    exchange_tls_connection(stream, server)
}

fn serve_two_tls_connections() -> (SocketAddr, JoinHandle<[usize; 2]>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    let address = listener.local_addr().expect("local listener address");
    let server = std::thread::spawn(move || {
        let mut received = [0; 2];
        for bytes in &mut received {
            let (stream, _) = listener.accept().expect("accept TLS connection");
            *bytes = serve_tls_connection(stream);
        }
        received
    });
    (address, server)
}

fn serve_two_mutual_tls_connections(
    client_pubkey: [u8; 32],
) -> (SocketAddr, JoinHandle<[usize; 2]>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    let address = listener.local_addr().expect("local listener address");
    let server = std::thread::spawn(move || {
        let mut received = [0; 2];
        for bytes in &mut received {
            let (stream, _) = listener.accept().expect("accept mutual TLS connection");
            *bytes = serve_mutual_tls_connection(stream, client_pubkey);
        }
        received
    });
    (address, server)
}

fn run_reconnect(endpoint: Endpoint<Client>, address: SocketAddr) {
    let config = dope::driver::Config::for_tcp_profile::<Balanced>(CONNECTIONS);
    let executor = Executor::new(config)
        .expect("executor")
        .with_storage_factory(
            ConnectorPort::<Tcp, ClientTls>::factory(CONNECTIONS).expect("connector storage"),
        );

    executor.enter(|mut session| {
        let storage = session.storage();
        let endpoint = endpoint.bind(storage.wire_storage());
        let mut driver = session.driver_access();
        let connector = storage
            .connector_with_wire(endpoint, &mut driver)
            .expect("client connector");
        let handle = storage.handle();
        session.with_app(App { connector }, |mut app| {
            for _ in 0..2 {
                let mut stream = app
                    .block_on(dope_gen::fiber!('_ => async move {
                        handle.connect(address, Default::default()).await
                    }))
                    .expect("drive connector")
                    .expect("connection becomes active");

                let (read, bytes, peer_closed) = app
                    .block_on(dope_gen::fiber!('_ => async move {
                        if let Err(error) = stream.write_all(PING).await {
                            return (Err(error), Vec::new(), false);
                        }
                        let (read, bytes) = stream.read(Vec::with_capacity(PONG.len())).await;
                        let (closed, tail) = stream.read(Vec::with_capacity(1)).await;
                        (read, bytes, closed.is_err() || tail.is_empty())
                    }))
                    .expect("drive TLS reply");
                read.expect("read TLS reply");
                assert_eq!(bytes, PONG);
                assert!(peer_closed, "server must drop each completed connection");
            }
        });
    });
}

#[test]
fn standard_client_endpoint_reconnects_after_peer_drop() {
    let (address, server) = serve_two_tls_connections();
    let server_pubkey = *SigningKey::from_seed(&KEY_SEED)
        .expect("server signing key")
        .pubkey()
        .expect("server public key");
    run_reconnect(
        Endpoint::client(client_config(server_pubkey)).unwrap(),
        address,
    );

    let received = server.join().expect("listener thread");
    assert!(
        received.into_iter().all(|bytes| bytes == PING.len()),
        "both dials must complete a TLS application round-trip"
    );
}

#[test]
fn mutual_client_endpoint_reconnects_after_peer_drop() {
    let client_signing = SigningKey::from_seed(&[0x6b; 32]).expect("client signing key");
    let client_pubkey = *client_signing.pubkey().expect("client public key");
    let (address, server) = serve_two_mutual_tls_connections(client_pubkey);
    let server_pubkey = *SigningKey::from_seed(&KEY_SEED)
        .expect("server signing key")
        .pubkey()
        .expect("server public key");
    let endpoint: Endpoint<Client> = Endpoint::client_mutual(
        client_config(server_pubkey),
        ClientCertSource::RawPublicKey {
            signing_key: client_signing,
        },
    )
    .unwrap();

    run_reconnect(endpoint, address);

    let received = server.join().expect("mutual TLS listener thread");
    assert!(
        received.into_iter().all(|bytes| bytes == PING.len()),
        "both mTLS dials must authenticate and complete an application round-trip"
    );
}
