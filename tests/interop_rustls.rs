#![cfg(feature = "rustls")]

use std::sync::Arc;

use dope_tls::{clock::WallClock, state::State};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::cipher_suite;
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme, SupportedCipherSuite,
};
use shin::asn1::{Reader, Tag};
use shin::cert::Cert;
use shin::client::{OwnedTrustAnchor, Verifier};
use shin::record::CipherSuite;
use shin::server::CertSource;
use shin::sig::SigningKey;

const HOSTNAME: &str = "interop.local";
const PUMP_CAP: usize = 64;

fn install_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
}

struct Pki {
    cert_der: Vec<u8>,
    signing: SigningKey,
    rustls_cert: CertificateDer<'static>,
    rustls_key: PrivateKeyDer<'static>,
    valid_at: u64,
}

fn extract_ed25519_seed(pkcs8: &[u8]) -> [u8; 32] {
    let mut r = Reader::new(pkcs8);
    let inner = r.read_tagged(Tag::SEQUENCE).unwrap();
    let mut ir = Reader::new(inner);
    let _version = ir.read_tagged(Tag::INTEGER).unwrap();
    let _alg = ir.read_tagged(Tag::SEQUENCE).unwrap();
    let outer_oct = ir.read_tagged(Tag::OCTET_STRING).unwrap();
    let mut or = Reader::new(outer_oct);
    let inner_oct = or.read_tagged(Tag::OCTET_STRING).unwrap();
    assert_eq!(inner_oct.len(), 32, "ed25519 seed length");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_oct);
    seed
}

fn make_pki() -> Pki {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let pkcs8 = key.serialize_der();
    let seed = extract_ed25519_seed(&pkcs8);
    let signing = SigningKey::from_seed(&seed).unwrap();

    let mut params = CertificateParams::new(vec![HOSTNAME.into()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, HOSTNAME);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).unwrap();
    let cert_der = cert.der().to_vec();

    let parsed = Cert::parse(&cert_der).unwrap();
    let nb = shin::time::UnixTime::from_time_value(&parsed.validity.not_before).unwrap();
    let na = shin::time::UnixTime::from_time_value(&parsed.validity.not_after).unwrap();
    let valid_at = (nb.0 + na.0) / 2;

    Pki {
        rustls_cert: CertificateDer::from(cert_der.clone()),
        rustls_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
        cert_der,
        signing,
        valid_at,
    }
}

fn provider_with_suite(suite: SupportedCipherSuite) -> Arc<CryptoProvider> {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        ..base
    })
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pinned cert mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls1.2 disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn rustls_server_config(pki: &Pki, suite: SupportedCipherSuite) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder_with_provider(provider_with_suite(suite))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![pki.rustls_cert.clone()], pki.rustls_key.clone_key())
        .unwrap();
    cfg.send_tls13_tickets = 0;
    Arc::new(cfg)
}

fn rustls_client_config(pki: &Pki, suite: SupportedCipherSuite) -> Arc<ClientConfig> {
    let provider = provider_with_suite(suite);
    let verifier = PinnedServerVerifier {
        expected: pki.rustls_cert.clone(),
        provider: provider.clone(),
    };
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    )
}

fn dope_client(pki: &Pki, suite: CipherSuite) -> State {
    State::new_client_with(
        shin::client::Config {
            verifier: Verifier::X509 {
                anchors: vec![OwnedTrustAnchor::from_cert_der(&pki.cert_der).unwrap()],
                hostname: HOSTNAME.as_bytes().to_vec(),
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        },
        WallClock::FixedMillis(pki.valid_at * 1000),
        move |c| c.set_cipher_suites(&[suite]),
    )
    .unwrap()
}

fn dope_server(pki: &Pki) -> State {
    State::new_server(shin::server::Config {
        source: CertSource::X509 {
            chain_der: vec![pki.cert_der.clone()],
            signing_key: pki.signing.clone(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_keys: None,
        accept_early_data: false,
    })
    .expect("valid server buffer layout")
}

fn pump<D>(dope: &mut State, peer: &mut rustls::ConnectionCommon<D>) {
    for _ in 0..PUMP_CAP {
        let mut progressed = false;

        let out = dope.pull_send();
        if !out.is_empty() {
            let mut cursor: &[u8] = &out;
            while !cursor.is_empty() {
                let n = peer.read_tls(&mut cursor).expect("peer read_tls");
                peer.process_new_packets()
                    .expect("peer process_new_packets");
                if n == 0 {
                    break;
                }
            }
            progressed = true;
        }

        while peer.wants_write() {
            let mut buf = Vec::new();
            peer.write_tls(&mut buf).expect("peer write_tls");
            if buf.is_empty() {
                break;
            }
            dope.read_tcp(&buf).expect("dope read_tcp");
            progressed = true;
        }

        if !progressed {
            break;
        }
    }
}

fn drain_app(dope: &mut State, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < want {
        match dope.pull_app() {
            Some(chunk) if !chunk.is_empty() => got.extend_from_slice(chunk.as_slice()),
            _ => break,
        }
    }
    got
}

fn suites() -> [(CipherSuite, SupportedCipherSuite); 3] {
    [
        (
            CipherSuite::Aes128GcmSha256,
            cipher_suite::TLS13_AES_128_GCM_SHA256,
        ),
        (
            CipherSuite::ChaCha20Poly1305Sha256,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
        (
            CipherSuite::Aes256GcmSha384,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
        ),
    ]
}

fn client_vs_rustls_server(shin_suite: CipherSuite, rustls_suite: SupportedCipherSuite) -> State {
    let pki = make_pki();
    let mut server =
        ServerConnection::new(rustls_server_config(&pki, rustls_suite)).expect("server conn");
    let mut client = dope_client(&pki, shin_suite);

    pump(&mut client, &mut server);

    assert!(
        client.is_established(),
        "dope-tls client handshake incomplete"
    );
    assert!(
        !server.is_handshaking(),
        "rustls server handshake incomplete"
    );

    let negotiated = server
        .negotiated_cipher_suite()
        .expect("server negotiated a suite");
    assert_eq!(
        negotiated.suite(),
        rustls_suite.suite(),
        "negotiated suite disagreement"
    );

    let req = b"dope-tls client -> rustls server";
    let n = client.write_app(req).expect("client write_app");
    assert_eq!(n, req.len());
    pump(&mut client, &mut server);
    let mut got = vec![0u8; req.len()];
    use std::io::Read;
    server
        .reader()
        .read_exact(&mut got)
        .expect("server read app");
    assert_eq!(got.as_slice(), req, "client->server round-trip");

    let reply = b"rustls server -> dope-tls client";
    use std::io::Write;
    server.writer().write_all(reply).expect("server write app");
    pump(&mut client, &mut server);
    let echoed = drain_app(&mut client, reply.len());
    assert_eq!(echoed.as_slice(), reply, "server->client round-trip");

    client
}

fn server_vs_rustls_client(rustls_suite: SupportedCipherSuite) -> State {
    let pki = make_pki();
    let name = ServerName::try_from(HOSTNAME).expect("server name");
    let mut client =
        ClientConnection::new(rustls_client_config(&pki, rustls_suite), name).expect("client conn");
    let mut server = dope_server(&pki);

    pump(&mut server, &mut client);

    assert!(
        server.is_established(),
        "dope-tls server handshake incomplete"
    );
    assert!(
        !client.is_handshaking(),
        "rustls client handshake incomplete"
    );

    let negotiated = client
        .negotiated_cipher_suite()
        .expect("client negotiated a suite");
    assert_eq!(
        negotiated.suite(),
        rustls_suite.suite(),
        "negotiated suite disagreement"
    );

    let req = b"rustls client -> dope-tls server";
    use std::io::Write;
    client.writer().write_all(req).expect("client write app");
    pump(&mut server, &mut client);
    let got = drain_app(&mut server, req.len());
    assert_eq!(got.as_slice(), req, "client->server round-trip");

    let reply = b"dope-tls server -> rustls client";
    let n = server.write_app(reply).expect("server write_app");
    assert_eq!(n, reply.len());
    pump(&mut server, &mut client);
    let mut echoed = vec![0u8; reply.len()];
    use std::io::Read;
    client
        .reader()
        .read_exact(&mut echoed)
        .expect("client read app");
    assert_eq!(echoed.as_slice(), reply, "server->client round-trip");

    server
}

#[test]
fn dope_tls_client_handshakes_with_rustls_server() {
    install_provider();
    for (shin_suite, rustls_suite) in suites() {
        client_vs_rustls_server(shin_suite, rustls_suite);
    }
}

#[test]
fn dope_tls_server_handshakes_with_rustls_client() {
    install_provider();
    for (_, rustls_suite) in suites() {
        server_vs_rustls_client(rustls_suite);
    }
}
