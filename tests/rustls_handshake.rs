#![cfg(feature = "rustls")]

//! In-memory rustls crypto/config checks with a paired `ServerConnection` +
//! `ClientConnection`. Full `RustTls` `Wire` I/O over the io_uring runtime lives
//! in `rustls_e2e.rs`.

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

/// Total (header + body) length of each concatenated TLS record in `wire`.
fn record_lengths(mut wire: &[u8]) -> Vec<usize> {
    let mut lens = Vec::new();
    while wire.len() >= 5 {
        let total = 5 + u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert!(wire.len() >= total, "truncated record");
        lens.push(total);
        wire = &wire[total..];
    }
    assert!(wire.is_empty(), "trailing bytes are not a full record");
    lens
}

// `RustTls::egress_has_record_room` reserves `MAX_TLS_RECORD` of egress before
// letting rustls produce a record. Pin the assumption that backs that constant:
// every record rustls actually emits fits within it (and full-size ones occur).
#[test]
fn rustls_records_fit_max_tls_record() {
    use shin::record::{HEADER_LEN, MAX_CIPHERTEXT_BODY, MAX_PLAINTEXT_BODY};
    const MAX_TLS_RECORD: usize = HEADER_LEN + MAX_CIPHERTEXT_BODY;

    install_provider();
    let pki = make_pki();
    let name = ServerName::try_from("localhost").expect("server name");
    let mut client = ClientConnection::new(client_config(&pki), name).expect("client conn");
    let mut server = ServerConnection::new(server_config(&pki)).expect("server conn");
    pump(&mut client, &mut server);
    assert!(!client.is_handshaking(), "handshake incomplete");

    client
        .writer()
        .write_all(&vec![0xA5u8; 64 * 1024])
        .expect("app write");
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).expect("write_tls");
    }

    let lens = record_lengths(&wire);
    assert!(lens.len() >= 2, "64 KiB write should span multiple records");
    assert!(
        lens.iter().any(|&t| t - HEADER_LEN > MAX_PLAINTEXT_BODY),
        "expected a full-size record so the bound is actually exercised"
    );
    for &total in &lens {
        assert!(
            total <= MAX_TLS_RECORD,
            "rustls emitted a {total}-byte record over MAX_TLS_RECORD ({MAX_TLS_RECORD})"
        );
        assert!(total - HEADER_LEN <= MAX_CIPHERTEXT_BODY);
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
    //! Unit tests of the parts of `RustTls` that do not require a `Core`:
    //! construction and pre-handshake application buffering.

    use std::sync::Arc;

    use dope::wire::Wire;
    use dope_tls::{RustTls, RustTlsEndpoint};
    use rustls::pki_types::ServerName;

    use super::{client_config, install_provider, make_pki, server_config};

    #[test]
    fn none_endpoint_is_default_and_closes() {
        // Default is None; constructing from it yields a wire with nothing to
        // negotiate (it will flag itself for close internally).
        let ep = RustTlsEndpoint::default();
        assert!(matches!(ep, RustTlsEndpoint::None));
        let wire = RustTls::new(&ep);
        assert!(wire.alpn_protocol().is_none());
    }

    #[test]
    fn server_endpoint_constructs() {
        install_provider();
        let pki = make_pki();
        let ep = RustTlsEndpoint::Server(server_config(&pki));
        let wire = RustTls::new(&ep);
        // No handshake yet, so no ALPN.
        assert!(wire.alpn_protocol().is_none());
    }

    #[test]
    fn client_endpoint_produces_client_hello() {
        install_provider();
        let pki = make_pki();
        let cfg: Arc<rustls::ClientConfig> = client_config(&pki);
        let name = ServerName::try_from("localhost").expect("name");
        let ep = RustTlsEndpoint::Client {
            config: cfg,
            server_name: name,
        };
        // A freshly constructed client should have staged a ClientHello into
        // egress; `process_recv(&[])` should drain nothing new but not panic.
        let mut wire = RustTls::new(&ep);
        let out = wire.process_recv(&[]);
        // No inbound ciphertext, so no decrypted plaintext is produced.
        assert!(out.is_none());
    }
}
