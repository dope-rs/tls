#![cfg(all(feature = "rustls", target_os = "linux"))]

//! End-to-end test of the `RustTls` wire over the real dope io_uring runtime: a
//! dope `Listener` runs `RustTls` server-side, a plain-thread rustls client does
//! a real TLS handshake over a TCP socket, and a multi-record (>16 KiB) reply is
//! driven back through the wire's egress path and verified byte-for-byte.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::Arc;
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
use dope_tls::{RustTls, RustTlsEndpoint};
use rcgen::{KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};

const REPLY_LEN: usize = 50_000; // > one 16 KiB TLS record: forces multi-record egress.

fn install_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
}

fn reply_payload() -> Vec<u8> {
    (0..REPLY_LEN as u32).map(|i| (i % 251) as u8).collect()
}

struct Pki {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn make_pki() -> Pki {
    let kp = KeyPair::generate_for(&PKCS_ED25519).expect("key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("params")
        .self_signed(&kp)
        .expect("self-sign");
    Pki {
        cert: CertificateDer::from(cert.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der())),
    }
}

fn server_config(pki: &Pki) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![pki.cert.clone()], pki.key.clone_key())
            .expect("server config"),
    )
}

fn client_config(pki: &Pki) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.cert.clone()).expect("trust cert");
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Replies with a fixed payload on the first decrypted app chunk, then closes.
struct ReplyApp {
    payload: Vec<u8>,
    closes: Rc<Cell<u32>>,
}

impl Application for ReplyApp {
    type Conn = ();
    type Wire = RustTls;

    fn on_chunk(
        &mut self,
        slot: &mut Slot<Self::Wire, listener::State<Self::Conn>>,
        _chunk: RecvChunk<'_>,
        aux: &mut listener::Aux,
        driver: &mut Driver,
    ) -> Outcome {
        // Empty header + the full payload as a `Shared` body: this goes through
        // the wire's `submit_send_vectored` with >16 KiB in one call, so RustTls
        // fragments it across multiple TLS records (the path the egress room gate
        // guards), and the runtime re-drives the remainder until fully sent.
        let buf = aux.write_buf_for(slot);
        let body = o3::buffer::Shared::copy_from_slice(&self.payload);
        let ud = slot.token();
        slot.submit_split_shared(buf, 0, body, ud, driver);
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
    listener: Listener<0, ReplyApp, Bundle<Tcp, RustTls, profile::Throughput>>,
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

#[test]
fn rustls_wire_multi_record_reply_round_trips() {
    install_provider();
    let pki = make_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);
    let want = reply_payload();

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
    let mut listener = Listener::<0, ReplyApp, Bundle<Tcp, RustTls, profile::Throughput>>::open_in(
        ReplyApp {
            payload: want.clone(),
            closes: closes.clone(),
        },
        listener_cfg,
        exec.driver_mut(),
    )
    .expect("open_in");
    listener.set_cfg(RustTlsEndpoint::Server(server_cfg));
    let addr = listener.local_addr().expect("local_addr");
    let mut app = pin!(App { listener });

    let client = std::thread::spawn(move || {
        let name = ServerName::try_from("localhost").expect("name");
        let mut conn = ClientConnection::new(client_cfg, name).expect("client conn");
        let mut sock = wait_for_addr(addr);
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(b"GET\n").expect("client request");
        tls.flush().ok();
        let mut got = vec![0u8; REPLY_LEN];
        let ok = tls.read_exact(&mut got).is_ok();
        (ok, got)
    });

    let closes_done = closes.clone();
    drive_until(&mut exec, app.as_mut(), move || closes_done.get() >= 1);

    let (ok, got) = client.join().expect("client join");
    assert!(ok, "client could not read the full {REPLY_LEN}-byte reply");
    assert_eq!(got, want, "reply bytes corrupted across record boundaries");
    assert_eq!(closes.get(), 1, "connection must close exactly once");
}
