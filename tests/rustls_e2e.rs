#![cfg(all(feature = "rustls", target_os = "linux"))]

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use dope::DriverContext;
use dope::manifold::Outcome;
use dope::manifold::env::Bundle;
use dope::manifold::listener::{self, Application, Listener, SlotEgress};
use dope::runtime::Executor;
use dope::runtime::profile;
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

struct ReplyApp {
    payload: Vec<u8>,
    closes: Rc<Cell<u32>>,
}

impl<'d> Application<'d> for ReplyApp {
    type Conn = ();
    type Wire = RustTls;

    fn chunk<R: RetainBytes>(
        self: Pin<&mut Self>,
        slot: &mut Slot<'d, Self::Wire, listener::State<Self::Conn>>,
        _chunk: R,
        aux: &mut listener::Aux,
        driver: &mut DriverContext<'_, 'd>,
    ) -> Outcome {
        let payload = &self.get_mut().payload;
        let buf = aux.write_buf_for(slot);
        let body = Bytes::copy_from_slice(payload).into_shared();
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
    listener: Listener<'d, 0, ReplyApp, Bundle<Tcp, RustTls, profile::Throughput>>,
}

#[test]
fn rustls_wire_multi_record_reply_round_trips() {
    install_provider();
    let pki = make_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);
    let want = reply_payload();

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
                &mut driver,
            )
            .expect("open_in")
        };
        let addr = listener.local_addr().expect("local_addr");
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
            let mut trailing = [0u8; 1];
            let closed = matches!(tls.read(&mut trailing), Ok(0));
            (ok, closed, got)
        });

        let closes_done = closes.clone();
        sess.with_app(App { listener }, |mut app| {
            drive_until(&mut app, move || closes_done.get() >= 1);
        });

        let (ok, closed, got) = client.join().expect("client join");
        assert!(ok, "client could not read the full {REPLY_LEN}-byte reply");
        assert!(closed, "client did not receive a clean TLS close");
        assert_eq!(got, want, "reply bytes corrupted across record boundaries");
        assert_eq!(closes.get(), 1, "connection must close exactly once");
    });
}
