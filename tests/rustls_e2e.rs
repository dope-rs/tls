#![cfg(all(feature = "rustls", target_os = "linux"))]

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
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
use dope_tls::rustls::{RustTls, RustTlsEndpoint};
use rcgen::{KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};

mod common;
use common::{drive_until, wait_for_addr};

const REPLY_LEN: usize = 50_000;
const REPLY_PREFIX: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
const SERVER_MAX_FRAGMENT_SIZE: usize = 8 * 1024;
const SERVER_MAX_PLAINTEXT: usize = SERVER_MAX_FRAGMENT_SIZE - 5;

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
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![pki.cert.clone()], pki.key.clone_key())
        .expect("server config");
    config.send_tls13_tickets = 0;
    config.max_fragment_size = Some(SERVER_MAX_FRAGMENT_SIZE);
    Arc::new(config)
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

struct ReplyApp {
    payload: Vec<u8>,
    closes: Rc<Cell<u32>>,
}

impl<'d> Application<'d> for ReplyApp {
    type Conn = ();
    type Wire = RustTls;
    type Hooks = Self;
}

impl<'d> ApplicationHooks<'d, ReplyApp> for ReplyApp {
    fn chunk<R: RetainBytes>(
        app: Pin<&mut ReplyApp>,
        slot: &mut Slot<'d, RustTls, State<()>>,
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
        _slot: &mut Slot<'d, RustTls, State<()>>,
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
    listener: Listener<'d, 'd, 0, ReplyApp, Bundle<Tcp, RustTls, profile::Throughput>>,
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

    fn reset(&mut self) {
        self.pending.clear();
        self.complete = 0;
    }
}

struct CountedTcp {
    inner: TcpStream,
    records: WireRecords,
}

impl CountedTcp {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            records: WireRecords::default(),
        }
    }
}

impl Read for CountedTcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.records.push(&buf[..read]);
        Ok(read)
    }
}

impl Write for CountedTcp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn rustls_vectored_reply_coalesces_records_and_closes() {
    install_provider();
    let pki = make_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);
    let want = reply_payload();

    let closes = Rc::new(Cell::new(0u32));
    let cfg = dope::driver::Config::for_tcp_profile::<profile::Throughput>(16);
    let exec = Executor::new(cfg)
        .expect("executor")
        .with_storage(EgressStorage::default());
    exec.enter(|mut sess| {
        let egress = sess.storage();
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
        let listener = {
            let mut driver = sess.driver_access();
            Listener::<0, ReplyApp, Bundle<Tcp, RustTls, profile::Throughput>>::open_in_with_wire(
                ReplyApp {
                    payload: want.clone(),
                    closes: closes.clone(),
                },
                listener_cfg,
                RustTlsEndpoint::Server(server_cfg),
                hash,
                egress,
                &mut driver,
            )
            .expect("open_in")
        };
        let addr = listener.local_addr().expect("local_addr");
        let client = std::thread::spawn(move || {
            let name = ServerName::try_from("localhost").expect("name");
            let mut conn = ClientConnection::new(client_cfg, name).expect("client conn");
            let mut sock = CountedTcp::new(wait_for_addr(addr));
            sock.inner
                .set_read_timeout(Some(Duration::from_secs(5)))
                .ok();
            while conn.is_handshaking() || conn.wants_write() {
                conn.complete_io(&mut sock).expect("client handshake");
            }
            sock.records.reset();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            tls.write_all(b"GET\n").expect("client request");
            tls.flush().ok();
            let mut got = vec![0u8; REPLY_LEN + REPLY_PREFIX.len()];
            let ok = tls.read_exact(&mut got).is_ok();
            let mut trailing = [0u8; 1];
            let closed = matches!(tls.read(&mut trailing), Ok(0));
            (ok, closed, got, sock.records)
        });

        let closes_done = closes.clone();
        sess.with_app(App { listener }, |mut app| {
            drive_until(&mut app, move || closes_done.get() >= 1);
        });

        let (ok, closed, got, records) = client.join().expect("client join");
        let mut expected = REPLY_PREFIX.to_vec();
        expected.extend(want);
        assert!(
            ok,
            "client could not read the full {}-byte reply",
            expected.len()
        );
        assert!(closed, "client did not receive a clean TLS close");
        assert_eq!(
            records.complete,
            expected.len().div_ceil(SERVER_MAX_PLAINTEXT) + 1,
            "vectored boundaries must not create extra records at the configured fragment size"
        );
        assert!(
            records.pending.is_empty(),
            "the server must not truncate its last rustls record"
        );
        assert_eq!(
            got, expected,
            "reply bytes corrupted across record boundaries"
        );
        assert_eq!(closes.get(), 1, "connection must close exactly once");
    });
}
