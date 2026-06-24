use dope_tls::{State, WebpkiRoots};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
use shin::asn1::{Reader, Tag};
use shin::cert::{Cert, SubjectPublicKeyInfo};
use shin::client::{OwnedTrustAnchor, Verifier};
use shin::server::CertSource;
use shin::sig::SigningKey;

const HOSTNAME: &str = "host.local";

fn extract_ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut r = Reader::new(pkcs8);
    let inner = r.expect(Tag::SEQUENCE).ok()?;
    let mut ir = Reader::new(inner);
    let _version = ir.expect(Tag::INTEGER).ok()?;
    let _alg = ir.expect(Tag::SEQUENCE).ok()?;
    let outer_oct = ir.expect(Tag::OCTET_STRING).ok()?;
    let mut or = Reader::new(outer_oct);
    let inner_oct = or.expect(Tag::OCTET_STRING).ok()?;
    if inner_oct.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(inner_oct);
    Some(seed)
}

fn ed25519_self_signed() -> (Vec<u8>, SigningKey) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let pkcs8 = key.serialize_der();
    let seed = extract_ed25519_seed(&pkcs8).expect("seed");
    let signing = SigningKey::from_seed(&seed).unwrap();
    let mut params = CertificateParams::new(vec![HOSTNAME.into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOSTNAME);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key).unwrap();
    (cert.der().to_vec(), signing)
}

fn pump(client: &mut State, server: &mut State) {
    for _ in 0..16 {
        let from_client = client.pull_send();
        let from_server = server.pull_send();
        let progressed = !from_client.is_empty() || !from_server.is_empty();
        if !from_client.is_empty() {
            server.read_tcp(&from_client).expect("server.read_tcp");
        }
        if !from_server.is_empty() {
            client.read_tcp(&from_server).expect("client.read_tcp");
        }
        if !progressed {
            break;
        }
    }
}

#[test]
fn webpki_roots_returns_nonempty_anchor_pool() {
    let pool = WebpkiRoots::anchors();
    assert!(
        pool.len() > 50,
        "expected >= 50 Mozilla roots, got {}",
        pool.len()
    );
    for ta in &pool {
        assert!(!ta.subject_der.is_empty());
        assert!(!ta.spki_der.is_empty());
    }
}

#[test]
fn webpki_roots_spki_round_trips_through_verifier_parse() {
    let pool = WebpkiRoots::anchors();
    assert!(!pool.is_empty());
    for ta in &pool {
        let spki = SubjectPublicKeyInfo::parse_standalone(&ta.spki_der).unwrap_or_else(|e| {
            panic!("anchor SPKI failed to parse: {e:?}");
        });
        assert!(
            !spki.algorithm.oid.is_empty(),
            "anchor SPKI missing algorithm OID"
        );
        assert!(
            !spki.subject_public_key.is_empty(),
            "anchor SPKI missing public key bytes"
        );
    }
}

#[test]
fn from_cert_der_extracts_anchor_fields() {
    let (cert_der, _) = ed25519_self_signed();
    let cert = Cert::parse(&cert_der).unwrap();
    let anchor = OwnedTrustAnchor::from_cert_der(&cert_der).unwrap();
    assert_eq!(anchor.subject_der, cert.subject_der);
    assert_eq!(anchor.spki_der, cert.spki.raw_der);
}

#[test]
fn x509_handshake_round_trip() {
    let (cert_der, signing) = ed25519_self_signed();
    let cert = Cert::parse(&cert_der).unwrap();
    let nb = shin::time::UnixTime::from_time_value(&cert.validity.not_before).unwrap();
    let na = shin::time::UnixTime::from_time_value(&cert.validity.not_after).unwrap();
    let now = (nb.0 + na.0) / 2;
    let anchor = OwnedTrustAnchor::from_cert_der(&cert_der).unwrap();

    let mut server = State::new_server(shin::server::Config {
        source: CertSource::X509 {
            chain_der: vec![cert_der.clone()],
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = State::new_client(shin::client::Config {
        verifier: Verifier::X509 {
            anchors: vec![anchor],
            hostname: HOSTNAME.as_bytes().to_vec(),
            now_seconds: now,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap();

    pump(&mut client, &mut server);
    assert!(client.is_established(), "client x509 handshake established");
    assert!(server.is_established(), "server x509 handshake established");

    let req = b"x509 ping";
    client.write_app(req).unwrap();
    pump(&mut client, &mut server);
    let got = server.pull_app().expect("server got app data");
    assert_eq!(got.as_slice(), req);
}
