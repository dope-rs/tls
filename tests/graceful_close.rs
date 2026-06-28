use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::time::Duration;

use dope::fiber::Fiber;
use dope::manifold::Outcome;
use dope::manifold::env::Bundle;
use dope::manifold::listener::config::Config;
use dope::manifold::listener::{self, Application, Listener};
use dope::runtime::profile;
use dope::transport::Tcp;
use dope::transport::config::tcp::ListenerOpts;
use dope::transport::link::Slot;
use dope::transport::wire::RecvChunk;
use dope::{Driver, DriverConfig, Executor};
use dope_tls::{Endpoint, PeerClose, State, Tls};

mod common;
use common::signing_key;

struct ReplyApp {
    closes: Rc<Cell<u32>>,
}

impl Application for ReplyApp {
    type Conn = ();
    type Wire = Tls;

    fn on_chunk(
        &mut self,
        _slot: &mut Slot<Self::Wire, listener::State<Self::Conn>>,
        _chunk: RecvChunk<'_>,
        _aux: &mut listener::Aux,
        _driver: &mut Driver,
    ) -> Outcome {
        Outcome::CloseAfter
    }

    fn on_send(
        &mut self,
        _slot: &mut Slot<Self::Wire, listener::State<Self::Conn>>,
        _sent: usize,
        _aux: &mut listener::Aux,
        _driver: &mut Driver,
    ) {
    }

    fn on_close(
        &mut self,
        _slot: &mut Slot<Self::Wire, listener::State<Self::Conn>>,
        _aux: &mut listener::Aux,
    ) {
        self.closes.set(self.closes.get() + 1);
    }
}

#[pin_project::pin_project]
#[derive(dope_gen::Dispatcher)]
struct App {
    #[pin]
    #[manifold]
    listener: Listener<0, ReplyApp, Bundle<Tcp, Tls, profile::Throughput>>,
}

fn wait_for_addr(addr: SocketAddr) -> TcpStream {
    for _ in 0..200 {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("could not connect to {addr}");
}

fn drive_until<F: FnMut() -> bool + 'static>(exec: &mut Executor, app: Pin<&mut App>, mut done: F) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let fiber = Fiber::new(std::future::poll_fn(move |cx| {
        if done() || std::time::Instant::now() >= deadline {
            std::task::Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }));
    dope_extra::block_on(exec, app, fiber);
}

fn run_client(mut sock: TcpStream, server_pubkey: [u8; 32]) -> PeerClose {
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

    for _ in 0..64 {
        match sock.read(&mut buf) {
            Ok(0) => {
                let _ = client.on_peer_eof();
                break;
            }
            Ok(n) => {
                if client.read_tcp(&buf[..n]).is_err() {
                    break;
                }
                let _ = client.pull_app();
            }
            Err(_) => {
                if client.peer_close() != PeerClose::Open {
                    break;
                }
            }
        }
    }
    client.peer_close()
}

#[test]
fn graceful_close_puts_close_notify_on_the_wire_before_fin() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    let closes = Rc::new(Cell::new(0u32));

    let cfg = <dope::DriverCfg as DriverConfig>::for_tcp_profile::<profile::Throughput>(16);
    let mut exec = Executor::new(cfg).expect("executor");

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind");
    let listener_cfg = Config::<Tcp> {
        max_conn: 16,
        bind,
        backlog: 128,
        stream_opts: Default::default(),
        listener_opts: ListenerOpts::default(),
    };
    let mut listener = Listener::<0, ReplyApp, Bundle<Tcp, Tls, profile::Throughput>>::open_in(
        ReplyApp {
            closes: closes.clone(),
        },
        listener_cfg,
        exec.driver_mut(),
    )
    .expect("open_in");
    listener.set_cfg(Endpoint::Server(Box::new(shin::server::Config {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_keys: None,
        accept_early_data: false,
    })));
    let addr = listener.local_addr().expect("local_addr");
    let mut app = pin!(App { listener });

    let client = std::thread::spawn(move || {
        let sock = wait_for_addr(addr);
        run_client(sock, server_pubkey)
    });

    let closes_done = closes.clone();
    drive_until(&mut exec, app.as_mut(), move || closes_done.get() >= 1);

    let peer_close = client.join().expect("client join");
    assert_eq!(
        peer_close,
        PeerClose::CloseNotify,
        "a graceful server close must emit a close_notify before the FIN, not a bare FIN (Truncated)"
    );
    assert_eq!(closes.get(), 1, "connection must close exactly once");
}
