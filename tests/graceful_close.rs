use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::time::Duration;

use dope::DriverContext;
use dope::manifold::Outcome;
use dope::manifold::env::Bundle;
use dope::manifold::listener::{self, Application, Listener, SlotEgress};
use dope::runtime::Executor;
use dope::runtime::profile;
use dope_net::link::slot::Slot;
use dope_net::tcp::Tcp;
use dope_tls::{
    state::{State, status::PeerClose},
    tls::{Endpoint, Tls},
};
use o3::buffer::RetainBytes;

mod common;
use common::{drive_until, signing_key, wait_for_addr};

const REPLY_LEN: usize = 50_000;

struct ReplyApp {
    payload: Vec<u8>,
    closes: Rc<Cell<u32>>,
}

impl<'d> Application<'d> for ReplyApp {
    type Conn = ();
    type Wire = Tls;

    fn chunk<R: RetainBytes>(
        self: Pin<&mut Self>,
        slot: &mut Slot<'d, Self::Wire, listener::State<Self::Conn>>,
        _chunk: R,
        aux: &mut listener::Aux,
        driver: &mut DriverContext<'_, 'd>,
    ) -> Outcome {
        let payload = &self.get_mut().payload;
        let buf = aux.write_buf_for(slot);
        let body = o3::buffer::Shared::copy_from_slice(payload);
        let ud = slot.token();
        slot.submit_split_shared(buf, 0, body, ud, driver);
        Outcome::CloseAfter
    }

    fn send(
        self: Pin<&mut Self>,
        _slot: &mut Slot<'d, Self::Wire, listener::State<Self::Conn>>,
        _sent: usize,
        _aux: &mut listener::Aux,
        _driver: &mut DriverContext<'_, 'd>,
    ) {
    }

    fn close(
        self: Pin<&mut Self>,
        _slot: &mut Slot<'d, Self::Wire, listener::State<Self::Conn>>,
        _aux: &mut listener::Aux,
    ) {
        let closes = &self.get_mut().closes;
        closes.set(closes.get() + 1);
    }
}

#[pin_project::pin_project]
#[derive(dope_gen::Dispatcher)]
struct App<'d> {
    #[pin]
    #[manifold]
    listener: Listener<'d, 0, ReplyApp, Bundle<Tcp, Tls, profile::Throughput>>,
}

fn run_client(mut sock: TcpStream, server_pubkey: [u8; 32]) -> (PeerClose, Vec<u8>) {
    let mut client = State::new_client(shin::client::Config {
        verifier: shin::client::Verifier::RawPublicKey {
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

    let mut received = Vec::with_capacity(REPLY_LEN);
    for _ in 0..64 {
        match sock.read(&mut buf) {
            Ok(0) => {
                let _ = client.peer_eof();
                break;
            }
            Ok(n) => {
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
    (client.peer_close(), received)
}

#[test]
fn graceful_close_puts_close_notify_on_the_wire_before_fin() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    let closes = Rc::new(Cell::new(0u32));

    let cfg = dope::driver::Config::for_tcp_profile::<profile::Throughput>(16);
    let exec = Executor::new(cfg).expect("executor");
    exec.enter(|mut sess| {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind");
    let listener_cfg = listener::Config::<Tcp> {
        max_connections: 16,
        bind,
        backlog: 128,
        stream: Default::default(),
        transport: Default::default(),
        egress: Default::default(),
    };
    let hash = sess.seed().derive(dope::hash::domain::ACCEPT).state();
    let mut listener = {
        let mut driver = sess.driver_access();
        Listener::<0, ReplyApp, Bundle<Tcp, Tls, profile::Throughput>>::open_in(
            ReplyApp {
                payload: (0..REPLY_LEN as u32).map(|i| (i % 251) as u8).collect(),
                closes: closes.clone(),
            },
            listener_cfg,
            hash,
            &mut driver,
        )
        .expect("open_in")
    };
    listener.set_config(Endpoint::Server(Box::new(shin::server::Config {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_keys: None,
        accept_early_data: false,
    })));
    let addr = listener.local_addr().expect("local_addr");
    let app = pin!(o3::cell::BrandCell::new(App { listener }));

    let client = std::thread::spawn(move || {
        let sock = wait_for_addr(addr);
        run_client(sock, server_pubkey)
    });

    let closes_done = closes.clone();
    drive_until(&mut sess, app.as_ref(), move || closes_done.get() >= 1);

    let (peer_close, received) = client.join().expect("client join");
    assert_eq!(
        peer_close,
        PeerClose::CloseNotify,
        "a graceful server close must emit a close_notify before the FIN, not a bare FIN (Truncated)"
    );
    let expected: Vec<u8> = (0..REPLY_LEN as u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(received, expected, "multi-record reply must precede close_notify");
    assert_eq!(closes.get(), 1, "connection must close exactly once");
    });
}
