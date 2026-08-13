use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread::JoinHandle;
use std::time::Duration;

use dope::manifold::timing::Balanced;
use dope::net::tcp::Tcp;
use dope::net::wire::Cursor as _;
use dope::runtime::executor::Executor;
use dope_fiber::extensions::AppSessionExt;
use dope_fiber::net::{
    connector::{Connector, Port},
    read::Lease,
};
use dope_tls::tls::{self, endpoints, roles};
use dope_tls::{ClientAuth, ClientCertVerifier, ClientIdentity, Identity};
use shin::crypto::sig::SigningKey;

const KEY_SEED: [u8; 32] = [0x5a; 32];
const PING: &[u8] = b"ping";
const PONG: &[u8] = b"pong";

const CONNECTIONS: usize = 1;
type ClientTls = tls::Tls<roles::Client>;
type ClientConnector<'scope, 'd> = Connector<'scope, 'd, 0, Tcp, ClientTls>;

fn copy_lease(mut lease: Lease<'_, '_, ClientTls>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(lease.remaining());
    while !lease.is_empty() {
        let chunk = lease.chunk();
        let amount = chunk.len();
        bytes.extend_from_slice(chunk);
        assert_eq!(lease.consume(amount), amount);
    }
    bytes
}

#[pin_project::pin_project]
#[derive(dope_gen::Application)]
struct App<'d, 'scope> {
    #[pin]
    #[manifold]
    connector: ClientConnector<'scope, 'd>,
    #[dispatcher(marker)]
    driver: ::core::marker::PhantomData<fn(&'d ()) -> &'d ()>,
}

fn client_config(server_pubkey: [u8; 32]) -> shin::client::config::Config {
    shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
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
    mut server: super::common::TestServer<G, V>,
) -> usize
where
    G: shin::server::config::EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
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
    exchange_tls_connection(stream, super::common::raw_server(signing_key))
}

fn serve_mutual_tls_connection(stream: std::net::TcpStream, client_pubkey: [u8; 32]) -> usize {
    let signing_key = SigningKey::from_seed(&KEY_SEED).expect("server signing key");
    let config = shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    };
    let shard = shin::server::Shard::with_client_auth(
        config,
        ClientAuth::Required,
        PinnedVerifier {
            expected_spki: client_spki(client_pubkey),
        },
    )
    .expect("mutual server shard");
    let server = super::common::TestServer::new(
        super::common::mutual_server_state(shard).expect("server state"),
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

fn run_reconnect(endpoint: endpoints::Configuration<roles::Client>, address: SocketAddr) {
    let config = dope::core::driver::settings::Config::for_tcp_profile::<Balanced>(CONNECTIONS)
        .expect("driver config");
    let executor = Executor::new(config)
        .expect("executor")
        .with_factory(Port::<Tcp, ClientTls>::factory(CONNECTIONS).expect("connector storage"));

    executor
        .try_enter(|mut session| {
            let storage = session.storage();
            let endpoint = endpoint.bind(storage.wire_storage());
            let mut driver = session.driver_access();
            let connector = storage
                .connector_with_wire(endpoint, &mut driver)
                .expect("client connector");
            let handle = storage.handle();
            session
                .with_app(
                    App {
                        connector,
                        driver: ::core::marker::PhantomData,
                    },
                    |mut app| {
                        for _ in 0..2 {
                            let mut stream = app
                                .block_on(dope_gen::fiber!('_, crate = ::dope_fiber => async move {
                                    handle.connect(address, Default::default()).await
                                }))
                                .expect("drive connector")
                                .expect("connection becomes active");

                            let (read, bytes, peer_closed) = app
                                .block_on(dope_gen::fiber!('_, crate = ::dope_fiber => async move {
                                    if let Err(error) = stream.write_all(PING).await {
                                        return (Err(error), Vec::new(), false);
                                    }
                                    let bytes = match stream.read().await {
                                        Ok(Some(lease)) => copy_lease(lease),
                                        Ok(None) => return (Ok(()), Vec::new(), true),
                                        Err(error) => return (Err(error), Vec::new(), false),
                                    };
                                    let peer_closed = match stream.read().await {
                                        Ok(None) => true,
                                        Ok(Some(_)) => false,
                                        Err(_) => true,
                                    };
                                    (Ok(()), bytes, peer_closed)
                                }))
                                .expect("drive TLS reply");
                            read.expect("read TLS reply");
                            assert_eq!(bytes, PONG);
                            assert!(peer_closed, "server must drop each completed connection");
                        }
                    },
                )
                .expect("connector app shutdown");
        })
        .expect("connector route");
}

#[test]
fn standard_client_endpoint_reconnects_after_peer_drop() {
    let _fixture = super::common::runtime_fixture();
    let (address, server) = serve_two_tls_connections();
    let server_pubkey = *SigningKey::from_seed(&KEY_SEED)
        .expect("server signing key")
        .pubkey()
        .expect("server public key");
    run_reconnect(
        endpoints::Configuration::client(client_config(server_pubkey)).unwrap(),
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
    let _fixture = super::common::runtime_fixture();
    let client_signing = SigningKey::from_seed(&[0x6b; 32]).expect("client signing key");
    let client_pubkey = *client_signing.pubkey().expect("client public key");
    let (address, server) = serve_two_mutual_tls_connections(client_pubkey);
    let server_pubkey = *SigningKey::from_seed(&KEY_SEED)
        .expect("server signing key")
        .pubkey()
        .expect("server public key");
    let endpoint: endpoints::Configuration<roles::Client> =
        endpoints::Configuration::client_mutual(
            client_config(server_pubkey),
            Identity::RawPublicKey {
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
