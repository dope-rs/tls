use dope::net::wire::{RuntimeLimits, Wire};
use dope_tls::Identity;
use dope_tls::Roots;
use dope_tls::tls::{self, endpoints, roles};
use shin::client::config::{Config, Error, MAX_TRUST_ANCHORS, OwnedTrustAnchor, Verifier};
use shin::crypto::sig::SigningKey;
use shin::identity::spki::SubjectPublicKey;

type ClientTls = tls::Tls<roles::Client>;

fn config_with_anchor_count(anchor_count: usize) -> Config {
    let anchor = OwnedTrustAnchor {
        subject_der: Vec::new(),
        spki_der: SubjectPublicKey::Ed25519([0; 32]).encode().unwrap(),
        name_constraints_der: None,
    };
    Config {
        verifier: Verifier::X509 {
            anchors: vec![anchor; anchor_count],
            hostname: b"example.com".to_vec(),
            certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
}

#[test]
fn complete_webpki_root_set_builds_a_client_runtime() {
    let roots = Roots::new().into_store().unwrap();
    assert!(roots.len() > 64, "test must cover the former limit");
    assert!(roots.len() <= MAX_TRUST_ANCHORS);
    let config = Config {
        verifier: Verifier::X509Store {
            roots,
            hostname: b"example.com".to_vec(),
            certificate_limit: shin::client::config::CertificateLimit::ONE_RECORD,
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"http/1.1".to_vec()],
        enable_early_data: false,
    };
    let storage = ClientTls::connection_storage::<0>(1).unwrap();
    let endpoint: endpoints::Configuration<roles::Client> =
        endpoints::Configuration::client(config).unwrap();

    ClientTls::runtime_context::<0>(RuntimeLimits::new(1, 0, 64 * 1024), endpoint.bind(&storage))
        .expect("the complete standard root set must build");
}

#[test]
fn invalid_client_config_fails_endpoint_construction_immediately() {
    let error = endpoints::Configuration::<roles::Client>::client(config_with_anchor_count(
        MAX_TRUST_ANCHORS + 1,
    ))
    .err()
    .expect("invalid client config");
    assert_eq!(
        error,
        dope_tls::Error::InvalidConfig(Error::TooManyTrustAnchors {
            count: MAX_TRUST_ANCHORS + 1,
            maximum: MAX_TRUST_ANCHORS,
        })
    );
    assert_eq!(
        error.to_string(),
        "invalid TLS client config: X.509 trust anchor count 257 exceeds maximum 256"
    );
    assert!(std::error::Error::source(&error).is_some_and(|source| {
        source.downcast_ref::<Error>()
            == Some(&Error::TooManyTrustAnchors {
                count: MAX_TRUST_ANCHORS + 1,
                maximum: MAX_TRUST_ANCHORS,
            })
    }));
}

#[test]
fn oversized_client_hello_fails_endpoint_construction_immediately() {
    let mut config = config_with_anchor_count(1);
    config.alpn_protocols = vec![vec![b'a'; u8::MAX as usize]; 200];
    assert!(matches!(
        endpoints::Configuration::<roles::Client>::client(config),
        Err(dope_tls::Error::InvalidConfig(
            Error::ClientHelloTooLarge { .. }
        ))
    ));
}

#[test]
fn invalid_mutual_identity_fails_endpoint_construction_immediately() {
    let endpoint = endpoints::Configuration::<roles::Client>::client_mutual(
        config_with_anchor_count(1),
        Identity::X509 {
            chain_der: Vec::new(),
            signing_key: SigningKey::from_seed(&[0x44; 32]).unwrap(),
        },
    );
    assert!(matches!(
        endpoint,
        Err(dope_tls::Error::InvalidConfig(Error::InvalidIdentity))
    ));
}

#[test]
fn invalid_server_name_fails_endpoint_construction_immediately() {
    let mut config = config_with_anchor_count(1);
    if let Verifier::X509 { hostname, .. } = &mut config.verifier {
        *hostname = b"bad\0host.example".to_vec();
    }
    assert_eq!(
        endpoints::Configuration::<roles::Client>::client(config).err(),
        Some(dope_tls::Error::InvalidConfig(Error::InvalidServerName))
    );
}
