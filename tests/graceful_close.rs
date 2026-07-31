use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use dope::DriverContext;
use dope::manifold::Outcome;
use dope::manifold::env::Bundle;
use dope::manifold::listener::Listener;
use dope::manifold::listener::application::{Application, ApplicationHooks};
use dope::manifold::listener::config::Config;
use dope::manifold::listener::egress::SlotEgress;
use dope::manifold::listener::state::{EgressCtx, State};
use dope::runtime::executor::Executor;
use dope::runtime::profile;
use dope_net::link::egress::storage::Storage as EgressStorage;
use dope_net::link::slot::Slot;
use dope_net::tcp::Tcp;
use dope_net::{Bytes, RetainBytes};
use dope_tls::{
    state::status::PeerClose,
    tls::{Endpoint, SessionStorage, Tls},
};

mod common;
use common::{drive_until, signing_key, wait_for_addr};

const REPLY_LEN: usize = 50_000;
const REPLY_PREFIX: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";

struct ReplyApp {
    payload: Vec<u8>,
    closes: Rc<Cell<u32>>,
}

impl<'d> Application<'d> for ReplyApp {
    type Conn = ();
    type Wire = Tls;
    type Hooks = Self;
}

impl<'d> ApplicationHooks<'d, ReplyApp> for ReplyApp {
    fn chunk<R: RetainBytes>(
        app: Pin<&mut ReplyApp>,
        slot: &mut Slot<'d, Tls, State<()>>,
        mut egress: EgressCtx<'_, '_>,
        _chunk: R,
        driver: &mut DriverContext<'_, 'd>,
    ) -> Outcome {
        let payload = &app.get_mut().payload;
        let mut buf = egress.write_buf_for(slot);
        buf[..REPLY_PREFIX.len()].copy_from_slice(REPLY_PREFIX);
        let body = Bytes::copy_from_slice(payload).into_shared();
        let ud = slot.token();
        slot.submit_split_shared(buf, REPLY_PREFIX.len(), body, ud, driver);
        Outcome::CloseAfter
    }

    fn close(
        app: Pin<&mut ReplyApp>,
        _slot: &mut Slot<'d, Tls, State<()>>,
        _egress: EgressCtx<'_, '_>,
    ) {
        let closes = &app.get_mut().closes;
        closes.set(closes.get() + 1);
    }
}

#[pin_project::pin_project]
#[derive(dope_gen::Dispatcher)]
struct App<'d> {
    #[pin]
    #[manifold]
    listener: Listener<'d, 'd, 0, ReplyApp, Bundle<Tcp, Tls, profile::Throughput>>,
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
    let mut client = common::ClientState::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
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
                    received.extend_from_slice(chunk.as_slice());
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
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    let closes = Rc::new(Cell::new(0u32));

    let cfg = dope::driver::Config::for_tcp_profile::<profile::Throughput>(16);
    let exec = Executor::new(cfg).expect("executor").with_storage((
        EgressStorage::default(),
        SessionStorage::try_with_capacity(16).expect("TLS session storage"),
    ));
    exec.enter(|mut sess| {
    let (egress, tls_storage) = sess.storage();
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind");
    let listener_cfg = Config::<Tcp> {
        max_connections: 16,
        bind,
        backlog: 128,
        stream: Default::default(),
        transport: Default::default(),
        egress: Default::default(),
    };
    let hash = sess.seed().derive(dope::hash::domain::ACCEPT).state();
    let endpoint = Endpoint::server(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: signing,
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let listener = {
        let mut driver = sess.driver_access();
        Listener::<0, ReplyApp, Bundle<Tcp, Tls, profile::Throughput>>::open_in_with_wire(
            ReplyApp {
                payload: (0..REPLY_LEN as u32).map(|i| (i % 251) as u8).collect(),
                closes: closes.clone(),
            },
            listener_cfg,
            endpoint.bind(tls_storage),
            hash,
            egress,
            &mut driver,
        )
        .expect("open_in")
    };
    let addr = listener.local_addr().expect("local_addr");
    let client = std::thread::spawn(move || {
        let sock = wait_for_addr(addr);
        run_client(sock, server_pubkey)
    });

    let closes_done = closes.clone();
    sess.with_app(App { listener }, |mut app| {
        drive_until(&mut app, move || closes_done.get() >= 1);
    });

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
