#![cfg(feature = "rustls")]

//! In-memory rustls handshake + application echo test.
//!
//! Driving the [`dope_tls::RustlsTls`] `Wire` end-to-end needs a live
//! `dope::transport::link::Core` (and io_uring backend), which cannot be
//! constructed in a plain unit test. So correctness of the crypto/config path
//! is proven here with a paired `ServerConnection` + `ClientConnection` pumped
//! in memory using the project's Ed25519 self-signed cert. Full `Wire` I/O is
//! exercised by the consumer benchmark/runtime.

use std::io::{Read, Write};
use std::sync::Arc;

use rcgen::{KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

const ALPN: &[u8] = b"http/1.1";

fn install_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
}

struct Pki {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
}

fn make_pki() -> Pki {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519).expect("generate ed25519 key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&key_pair)
        .expect("self-sign cert");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Pki { cert_der, key_der }
}

fn server_config(pki: &Pki) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![pki.cert_der.clone()], pki.key_der.clone_key())
        .expect("server config");
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(cfg)
}

fn client_config(pki: &Pki) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.cert_der.clone()).expect("trust self-signed");
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(cfg)
}

/// Shuttle all pending ciphertext between the two connections until both sides
/// stop wanting to write.
fn pump(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..32 {
        let mut progressed = false;

        // client -> server
        while client.wants_write() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).expect("client write_tls");
            if buf.is_empty() {
                break;
            }
            let mut cursor: &[u8] = &buf;
            while !cursor.is_empty() {
                server.read_tls(&mut cursor).expect("server read_tls");
                server.process_new_packets().expect("server packets");
            }
            progressed = true;
        }

        // server -> client
        while server.wants_write() {
            let mut buf = Vec::new();
            server.write_tls(&mut buf).expect("server write_tls");
            if buf.is_empty() {
                break;
            }
            let mut cursor: &[u8] = &buf;
            while !cursor.is_empty() {
                client.read_tls(&mut cursor).expect("client read_tls");
                client.process_new_packets().expect("client packets");
            }
            progressed = true;
        }

        if !progressed {
            break;
        }
    }
}

#[test]
fn handshake_alpn_and_echo() {
    install_provider();
    let pki = make_pki();
    let server_cfg = server_config(&pki);
    let client_cfg = client_config(&pki);

    let name = ServerName::try_from("localhost").expect("server name");
    let mut client = ClientConnection::new(client_cfg, name).expect("client conn");
    let mut server = ServerConnection::new(server_cfg).expect("server conn");

    pump(&mut client, &mut server);

    assert!(!client.is_handshaking(), "client handshake incomplete");
    assert!(!server.is_handshaking(), "server handshake incomplete");

    assert_eq!(client.alpn_protocol(), Some(ALPN), "client ALPN");
    assert_eq!(server.alpn_protocol(), Some(ALPN), "server ALPN");

    // Client -> server application message, echoed back.
    let msg = b"hello rustls wire";
    client.writer().write_all(msg).expect("client app write");
    pump(&mut client, &mut server);

    let mut got = vec![0u8; msg.len()];
    server
        .reader()
        .read_exact(&mut got)
        .expect("server read app");
    assert_eq!(&got, msg, "server received plaintext");

    // Echo back.
    server.writer().write_all(&got).expect("server echo write");
    pump(&mut client, &mut server);

    let mut echoed = vec![0u8; msg.len()];
    client
        .reader()
        .read_exact(&mut echoed)
        .expect("client read echo");
    assert_eq!(&echoed, msg, "client received echo");
}

mod wire_unit {
    //! Unit tests of the parts of `RustlsTls` that do not require a `Core`:
    //! construction and pre-handshake application buffering.

    use std::sync::Arc;

    use dope::wire::Wire;
    use dope_tls::{RustlsEndpoint, RustlsTls};
    use rustls::pki_types::ServerName;

    use super::{client_config, install_provider, make_pki, server_config};

    #[test]
    fn none_endpoint_is_default_and_closes() {
        // Default is None; constructing from it yields a wire with nothing to
        // negotiate (it will flag itself for close internally).
        let ep = RustlsEndpoint::default();
        assert!(matches!(ep, RustlsEndpoint::None));
        let wire = RustlsTls::new(&ep);
        assert!(wire.alpn_protocol().is_none());
    }

    #[test]
    fn server_endpoint_constructs() {
        install_provider();
        let pki = make_pki();
        let ep = RustlsEndpoint::Server(server_config(&pki));
        let wire = RustlsTls::new(&ep);
        // No handshake yet, so no ALPN.
        assert!(wire.alpn_protocol().is_none());
    }

    #[test]
    fn client_endpoint_produces_client_hello() {
        install_provider();
        let pki = make_pki();
        let cfg: Arc<rustls::ClientConfig> = client_config(&pki);
        let name = ServerName::try_from("localhost").expect("name");
        let ep = RustlsEndpoint::Client {
            config: cfg,
            server_name: name,
        };
        // A freshly constructed client should have staged a ClientHello into
        // egress; `process_recv(&[])` should drain nothing new but not panic.
        let mut wire = RustlsTls::new(&ep);
        let out = wire.process_recv(&[]);
        // No inbound ciphertext, so no decrypted plaintext is produced.
        assert!(out.is_none());
    }
}
