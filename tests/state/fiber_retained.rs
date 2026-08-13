use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use dope::manifold::listener::{self, config::Config};
use dope::manifold::timing::Balanced;
use dope::net::tcp::Tcp;
use dope::net::wire::Cursor as _;
use dope::runtime::executor::Executor;
use dope_fiber::extensions::AppSessionExt;
use dope_fiber::net::{
    read::Lease,
    server::{Listener, ListenerPort},
};
use dope_tls::tls::{self, endpoints};

use crate::common::ClientState;

const FIRST: &[u8] = b"fragmented";
const SECOND: &[u8] = b"-provided";
const TAIL_RECORDS: usize = 33;
const MAX_CONNECTIONS: usize = 4;

type Pool<'scope, 'd> = Listener<'scope, 'd, 0, Tcp, tls::Tls>;

#[pin_project::pin_project]
#[derive(dope_gen::Application)]
struct App<'d, 'scope> {
    #[pin]
    #[manifold]
    pool: Pool<'scope, 'd>,
    #[dispatcher(marker)]
    driver: ::core::marker::PhantomData<fn(&'d ()) -> &'d ()>,
}

fn client_state(server_pubkey: [u8; 32]) -> ClientState {
    ClientState::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    })
    .expect("client state")
}

fn reserve_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve address")
        .local_addr()
        .expect("reserved address")
}

fn run_client(addr: SocketAddr, server_pubkey: [u8; 32]) -> Vec<u8> {
    let mut socket = TcpStream::connect(addr).expect("connect");
    socket.set_nodelay(true).expect("nodelay");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    let mut client = client_state(server_pubkey);
    let mut input = [0; 16 * 1024];

    for _ in 0..64 {
        let outgoing = client.pull_send();
        if !outgoing.is_empty() {
            socket.write_all(&outgoing).expect("write handshake");
        }
        if client.is_established() {
            break;
        }
        let read = socket.read(&mut input).expect("read handshake");
        assert_ne!(read, 0, "server closed during handshake");
        client.read_tcp(&input[..read]).expect("process handshake");
    }
    assert!(client.is_established(), "handshake did not complete");
    let finished = client.pull_send();
    if !finished.is_empty() {
        socket.write_all(&finished).expect("write finished");
    }

    client.write_app(FIRST).expect("seal first");
    let first = client.pull_send();
    client.write_app(SECOND).expect("seal second");
    let second = client.pull_send();
    assert!(first.len() > 3);
    socket.write_all(&first[..3]).expect("write record prefix");
    std::thread::sleep(Duration::from_millis(100));
    let mut rest = first[3..].to_vec();
    rest.extend_from_slice(&second);
    for _ in 0..TAIL_RECORDS {
        client.write_app(b"x").expect("seal retained tail");
        rest.extend_from_slice(&client.pull_send());
    }
    socket.write_all(&rest).expect("write record remainder");

    let mut received = Vec::new();
    while received.is_empty() {
        let read = socket.read(&mut input).expect("read reply");
        assert_ne!(read, 0, "server closed before reply");
        client.read_tcp(&input[..read]).expect("process reply");
        while let Some(chunk) = client.pull_app() {
            received.extend_from_slice(&chunk);
        }
    }
    received
}

#[test]
fn fragmented_and_many_provided_records_share_retained_cursors() {
    let _fixture = super::common::runtime_fixture();
    let signing = super::common::signing_key();
    let server_pubkey = *signing.pubkey().expect("server public key");
    let endpoint = endpoints::Configuration::server(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: signing,
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .expect("server endpoint");
    let addr = reserve_addr();
    let executor = Executor::new(
        dope::core::driver::settings::Config::for_tcp_profile::<Balanced>(MAX_CONNECTIONS)
            .expect("driver config"),
    )
    .expect("executor")
    .with_factory(ListenerPort::<tls::Tls>::factory(MAX_CONNECTIONS).expect("listener storage"));

    executor
        .try_enter(|mut session| {
            let hash = session.hash_state(listener::Domain::DEFAULT);
            let storage = session.storage();
            let mut driver = session.driver_access();
            let config = Config {
                max_connections: MAX_CONNECTIONS,
                direct_flights: MAX_CONNECTIONS,
                bind: addr,
                backlog: 16,
                stream: Default::default(),
                transport: Default::default(),
                egress: Default::default(),
            };
            let endpoint = endpoint.bind(storage.wire_storage());
            let pool =
                Pool::bind_with_wire(storage, &mut driver, config, endpoint, hash).expect("bind");
            let accepts = session.storage().handle();
            let client = std::thread::spawn(move || run_client(addr, server_pubkey));
            let received = session
                .with_app(
                    App {
                        pool,
                        driver: ::core::marker::PhantomData,
                    },
                    |mut app| {
                        let stream = app
                            .block_on(dope_gen::fiber!('_, crate = ::dope_fiber => async move {
                                accepts.accept().await
                            }))
                            .expect("drive accept")
                            .expect("accept");
                        let mut stream = Some(stream);
                        app.block_on(dope_gen::fiber!('_, crate = ::dope_fiber => async move {
                            let mut stream = stream.take().expect("stream owner");
                            let expected = FIRST.len() + SECOND.len() + TAIL_RECORDS;
                            let mut received = Vec::with_capacity(expected);
                            let mut retained = None;
                            while received.len() < expected {
                                if retained.as_ref().is_none_or(Lease::is_empty) {
                                    retained = stream.read().await?;
                                }
                                let lease = retained
                                    .as_mut()
                                    .ok_or(std::io::ErrorKind::UnexpectedEof)?;
                                let want = (received.len() % 3 + 1).min(expected - received.len());
                                let chunk = lease.chunk();
                                let amount = want.min(chunk.len());
                                received.extend_from_slice(&chunk[..amount]);
                                assert_eq!(lease.consume(amount), amount);
                            }
                            stream.write_all(b"!").await?;
                            Ok::<_, std::io::Error>(received)
                        }))
                        .expect("drive receive")
                    },
                )
                .expect("drive retained plaintext")
                .expect("read retained plaintext");

            let mut expected = FIRST.to_vec();
            expected.extend_from_slice(SECOND);
            expected.extend(std::iter::repeat_n(b'x', TAIL_RECORDS));
            assert_eq!(received, expected);
            assert_eq!(client.join().expect("client thread"), b"!");
        })
        .expect("listener port storage");
}
