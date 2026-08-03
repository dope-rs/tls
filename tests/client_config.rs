use std::error::Error;

use dope_net::wire::{OpenReservation, RuntimeLimits, Wire};
use dope_tls::ClientCertSource;
use dope_tls::roots::WebPkiRoots;
use dope_tls::tls::{Client, ClientDial, ClientSetup, ClientSource, Endpoint, Tls};
use shin::client::config::{Config, ConfigError, MAX_TRUST_ANCHORS, OwnedTrustAnchor, Verifier};
use shin::crypto::sig::SigningKey;
use shin::identity::spki::SubjectPublicKey;

type ClientTls = Tls<Client>;

struct DynamicSource(ClientSetup);

impl ClientSource for DynamicSource {
    fn next(&mut self) -> ClientDial {
        self.0.for_next_dial()
    }
}

fn config_with_anchor_count(anchor_count: usize) -> Config {
    let anchor = OwnedTrustAnchor {
        subject_der: vec![0x30, 0x00],
        spki_der: SubjectPublicKey::Ed25519([0; 32]).encode().unwrap(),
    };
    Config {
        verifier: Verifier::X509 {
            anchors: vec![anchor; anchor_count],
            hostname: b"example.com".to_vec(),
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    }
}

#[test]
fn complete_webpki_root_set_builds_a_client_runtime() {
    let anchors: Vec<_> = WebPkiRoots::new().collect();
    assert!(anchors.len() > 64, "test must cover the former limit");
    assert!(anchors.len() <= MAX_TRUST_ANCHORS);
    let config = Config {
        verifier: Verifier::X509 {
            anchors,
            hostname: b"example.com".to_vec(),
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"http/1.1".to_vec()],
        resumption: None,
        enable_early_data: false,
    };
    let storage = ClientTls::connection_storage(1).unwrap();
    let endpoint: Endpoint<Client> = Endpoint::client(config).unwrap();

    ClientTls::runtime_context(RuntimeLimits::new(1, 0, 64 * 1024), endpoint.bind(&storage))
        .expect("the complete standard root set must build");
}

#[test]
fn invalid_client_config_fails_endpoint_construction_immediately() {
    let error = Endpoint::client(config_with_anchor_count(MAX_TRUST_ANCHORS + 1))
        .err()
        .expect("invalid client config");
    assert_eq!(
        error,
        dope_tls::error::Error::InvalidConfig(ConfigError::TooManyTrustAnchors {
            count: MAX_TRUST_ANCHORS + 1,
            maximum: MAX_TRUST_ANCHORS,
        })
    );
    assert_eq!(
        error.to_string(),
        "invalid TLS client config: X.509 trust anchor count 257 exceeds maximum 256"
    );
    assert!(error.source().is_some_and(|source| {
        source.downcast_ref::<ConfigError>()
            == Some(&ConfigError::TooManyTrustAnchors {
                count: MAX_TRUST_ANCHORS + 1,
                maximum: MAX_TRUST_ANCHORS,
            })
    }));
}

#[test]
fn invalid_config_cannot_become_a_client_setup() {
    assert!(matches!(
        ClientSetup::new(config_with_anchor_count(MAX_TRUST_ANCHORS + 1)),
        Err(dope_tls::error::Error::InvalidConfig(
            ConfigError::TooManyTrustAnchors { .. }
        ))
    ));
}

#[test]
fn a_custom_source_is_total_across_repeated_opens() {
    type DynamicTls = Tls<Client<DynamicSource>>;

    let setup = ClientSetup::new(config_with_anchor_count(1)).unwrap();
    let storage = DynamicTls::connection_storage(2).unwrap();
    let endpoint = Endpoint::client_source(DynamicSource(setup));
    let mut runtime =
        DynamicTls::runtime_context(RuntimeLimits::new(2, 0, 64 * 1024), endpoint.bind(&storage))
            .unwrap();

    let first = DynamicTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    let second = DynamicTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    drop((first, second));
}

#[test]
fn oversized_client_hello_fails_endpoint_construction_immediately() {
    let mut config = config_with_anchor_count(1);
    config.alpn_protocols = vec![vec![b'a'; u8::MAX as usize]; 200];
    assert!(matches!(
        Endpoint::client(config),
        Err(dope_tls::error::Error::InvalidConfig(
            ConfigError::ClientHelloTooLarge { .. }
        ))
    ));
}

#[test]
fn invalid_mutual_identity_fails_endpoint_construction_immediately() {
    let endpoint = Endpoint::client_mutual(
        config_with_anchor_count(1),
        ClientCertSource::X509 {
            chain_der: Vec::new(),
            signing_key: SigningKey::from_seed(&[0x44; 32]).unwrap(),
        },
    );
    assert!(matches!(
        endpoint,
        Err(dope_tls::error::Error::InvalidConfig(
            ConfigError::InvalidClientIdentity
        ))
    ));
}

#[test]
fn invalid_server_name_fails_endpoint_construction_immediately() {
    let mut config = config_with_anchor_count(1);
    if let Verifier::X509 { hostname, .. } = &mut config.verifier {
        *hostname = b"bad\0host.example".to_vec();
    }
    assert_eq!(
        Endpoint::client(config).err(),
        Some(dope_tls::error::Error::InvalidConfig(
            ConfigError::InvalidServerName
        ))
    );
}
