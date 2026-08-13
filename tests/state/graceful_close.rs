use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use dope::core::driver::retained::Context;
use dope::manifold::Bundle;
use dope::manifold::Outcome;
use dope::manifold::listener::handler::Application;
use dope::manifold::listener::{self, Listener, config::Config, connection};
use dope::manifold::timing;
use dope::net::tcp::Tcp;
use dope::runtime::executor::Executor;
use dope_tls::{
    state::status::PeerClose,
    tls::{self, endpoints},
};
use o3::buffer::bytes::{Bytes, Retainable};

use crate::common::{drive_until, signing_key, wait_for_addr};

const REPLY_LEN: usize = 50_000;
const REPLY_PREFIX: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";

struct ReplyApp {
    payload: Vec<u8>,
    closes: Rc<Cell<u32>>,
}

impl<'d, const ID: u8> Application<'d, ID> for ReplyApp {
    type Conn = ();
    type Wire = tls::Tls;
    type Input = dope::manifold::receive::Borrowed;

    fn deadline(self: Pin<&Self>) -> Option<std::time::Instant> {
        None
    }

    fn close(self: Pin<&mut Self>, _connection: connection::Ctx<'_, 'd, ID, tls::Tls, ()>) {
        let closes = &self.get_mut().closes;
        closes.set(closes.get() + 1);
    }
}

impl<'d, const ID: u8> dope::manifold::listener::handler::BorrowedApplication<'d, ID> for ReplyApp {
    fn chunk<R: Retainable>(
        self: Pin<&mut Self>,
        mut connection: connection::Ctx<'_, 'd, ID, tls::Tls, ()>,
        _chunk: R,
        driver: &mut Context<'_, '_, 'd>,
    ) -> Outcome {
        let payload = &self.get_mut().payload;
        let Some(mut write) = connection.try_write() else {
            return Outcome::CloseAfter;
        };
        write[..REPLY_PREFIX.len()].copy_from_slice(REPLY_PREFIX);
        let body = Bytes::copy_from_slice(payload).into_shared();
        write.submit_shared(REPLY_PREFIX.len(), body, driver);
        Outcome::CloseAfter
    }
}

#[pin_project::pin_project]
#[derive(dope_gen::Application)]
struct App<'d> {
    #[pin]
    #[manifold]
    listener: Listener<'d, 0, ReplyApp, Bundle<Tcp, tls::Tls, timing::Throughput>>,
}

#[derive(Default)]
struct WireRecords {
    pending: Vec<u8>,
    complete: usize,
}

impl WireRecords {
    fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        let mut consumed = 0;
        while self.pending.len() - consumed >= 5 {
            let body_len =
                u16::from_be_bytes([self.pending[consumed + 3], self.pending[consumed + 4]])
                    as usize;
            let record_len = 5 + body_len;
            if self.pending.len() - consumed < record_len {
                break;
            }
            consumed += record_len;
            self.complete += 1;
        }
        self.pending.drain(..consumed);
    }
}

fn run_client(mut sock: TcpStream, server_pubkey: [u8; 32]) -> (PeerClose, Vec<u8>, WireRecords) {
    let mut client = super::common::ClientState::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    })
    .expect("client");
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let mut buf = [0u8; 16384];
    for _ in 0..64 {
        if client.is_established() {
            break;
        }
        let out = client.pull_send();
        if !out.is_empty() {
            sock.write_all(&out).expect("write handshake");
        }
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => client.read_tcp(&buf[..n]).expect("read_tcp handshake"),
            Err(_) => {}
        }
    }
    assert!(client.is_established(), "client handshake must complete");

    let finished = client.pull_send();
    if !finished.is_empty() {
        sock.write_all(&finished).expect("write finished");
    }
    client.write_app(b"GET\n").expect("write_app");
    let req = client.pull_send();
    if !req.is_empty() {
        sock.write_all(&req).expect("write request");
    }

    let mut received = Vec::with_capacity(REPLY_LEN + REPLY_PREFIX.len());
    let mut records = WireRecords::default();
    for _ in 0..64 {
        match sock.read(&mut buf) {
            Ok(0) => {
                let _ = client.peer_eof();
                break;
            }
            Ok(n) => {
                records.push(&buf[..n]);
                if client.read_tcp(&buf[..n]).is_err() {
                    break;
                }
                while let Some(chunk) = client.pull_app() {
                    received.extend_from_slice(chunk.as_ref());
                }
            }
            Err(_) => {
                if client.peer_close() != PeerClose::Open {
                    break;
                }
            }
        }
    }
    (client.peer_close(), received, records)
}

#[test]
fn vectored_reply_coalesces_records_before_graceful_close() {
    let _fixture = super::common::runtime_fixture();
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    let closes = Rc::new(Cell::new(0u32));

    let cfg = dope::core::driver::settings::Config::for_tcp_profile::<timing::Throughput>(16)
        .expect("driver config");
    let exec = Executor::new(cfg).expect("executor").with_storage(
        endpoints::SessionStorage::try_with_capacity(16).expect("TLS session storage"),
    );
    exec.enter(|mut sess| {
        let hash = sess.hash_state(listener::Domain::DEFAULT);
        let tls_storage = sess.storage();
        let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind");
        let listener_cfg = Config::<Tcp> {
            max_connections: 16,
            direct_flights: 16,
            bind,
            backlog: 128,
            stream: Default::default(),
            transport: Default::default(),
            egress: Default::default(),
        };
        let endpoint = endpoints::Configuration::server(shin::server::config::Config {
            source: shin::server::config::CertSource::RawPublicKey {
                signing_key: signing,
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        })
        .unwrap();
        let listener = {
            let mut driver = sess.driver_access();
            Listener::<0, ReplyApp, Bundle<Tcp, tls::Tls, timing::Throughput>>::open_in_with_wire(
                ReplyApp {
                    payload: (0..REPLY_LEN as u32).map(|i| (i % 251) as u8).collect(),
                    closes: closes.clone(),
                },
                listener_cfg,
                endpoint.bind(tls_storage),
                hash,
                &mut driver,
            )
            .expect("open_in")
        };
        let addr = listener.local_addr();
        let client = std::thread::spawn(move || {
            let sock = wait_for_addr(addr);
            run_client(sock, server_pubkey)
        });

        let closes_done = closes.clone();
        sess.with_app(App { listener }, |mut app| {
            drive_until(&mut app, move || closes_done.get() >= 1);
        })
        .expect("listener app shutdown");

        let (peer_close, received, records) = client.join().expect("client join");
        assert_eq!(
            peer_close,
            PeerClose::CloseNotify,
            "a graceful server close must emit a close_notify before the FIN, not a bare FIN (Truncated)"
        );
        let mut expected = REPLY_PREFIX.to_vec();
        expected.extend((0..REPLY_LEN as u32).map(|i| (i % 251) as u8));
        assert_eq!(
            records.complete,
            expected
                .len()
                .div_ceil(shin::wire::record::MAX_PLAINTEXT_BODY)
                + 1,
            "vectored boundaries must not create extra application records"
        );
        assert!(
            records.pending.is_empty(),
            "the server must not truncate its last TLS record"
        );
        assert_eq!(received, expected, "multi-record reply must precede close_notify");
        assert_eq!(closes.get(), 1, "connection must close exactly once");
    });
}
