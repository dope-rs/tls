mod common;

use common::{TestServer, pump, signing_key};
use dope_tls::{ClientAuth, ClientCertSource, ClientCertVerifier, ClientIdentity, state::State};

struct PinnedVerifier {
    expected_spki: Vec<u8>,
}

impl ClientCertVerifier for PinnedVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        identity.spki_der == self.expected_spki.as_slice()
    }
}

fn client_spki(pubkey: [u8; 32]) -> Vec<u8> {
    shin::spki::SubjectPublicKey::Ed25519(pubkey)
        .encode()
        .unwrap()
}

fn server_config(signing: shin::sig::SigningKey) -> shin::server::Config {
    shin::server::Config {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: signing,
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    }
}

fn client_config(server_pubkey: [u8; 32]) -> shin::client::Config {
    shin::client::Config {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    }
}

fn server(
    config: shin::server::Config,
    verifier: PinnedVerifier,
) -> TestServer<shin::server::NoGuard, PinnedVerifier> {
    config.validate().unwrap();
    TestServer::new(
        State::new_server(shin::server::ConnectionConfig {
            transport_params: Vec::new(),
        })
        .unwrap(),
        shin::server::Shard::with_client_auth(config, ClientAuth::Required, verifier),
    )
}

#[test]
fn required_client_auth_completes_and_pins_spki() {
    let server_signing = signing_key();
    let server_pubkey = *server_signing.pubkey().unwrap();
    let client_signing = signing_key();
    let client_pubkey = *client_signing.pubkey().unwrap();

    let mut server = server(
        server_config(server_signing),
        PinnedVerifier {
            expected_spki: client_spki(client_pubkey),
        },
    );
    let mut client = State::new_client_mutual(
        client_config(server_pubkey),
        ClientCertSource::RawPublicKey {
            signing_key: client_signing,
        },
    )
    .unwrap();

    pump(&mut client, &mut server);

    assert!(client.is_established(), "client handshake must complete");
    assert!(server.is_established(), "server handshake must complete");

    client.write_app(b"client to server").unwrap();
    server.read_tcp(&client.pull_send()).unwrap();
    assert_eq!(server.pull_app().unwrap().as_slice(), b"client to server");

    server.write_app(b"server to client").unwrap();
    client
        .read_client_tcp(&server.pull_send())
        .expect("client read");
    assert_eq!(client.pull_app().unwrap().as_slice(), b"server to client");
}

#[test]
fn required_server_rejects_anonymous_client() {
    let server_signing = signing_key();
    let server_pubkey = *server_signing.pubkey().unwrap();

    let mut server = server(
        server_config(server_signing),
        PinnedVerifier {
            expected_spki: vec![0u8; 44],
        },
    );
    let mut client = State::new_client(client_config(server_pubkey)).unwrap();

    pump(&mut client, &mut server);

    assert!(!server.is_established());
    assert!(server.is_closed());
}

#[test]
fn required_server_rejects_unauthorized_client() {
    let server_signing = signing_key();
    let server_pubkey = *server_signing.pubkey().unwrap();
    let authorized_signing = signing_key();
    let authorized_pubkey = *authorized_signing.pubkey().unwrap();

    let mut server = server(
        server_config(server_signing),
        PinnedVerifier {
            expected_spki: client_spki(authorized_pubkey),
        },
    );

    let other_signing = signing_key();
    let mut client = State::new_client_mutual(
        client_config(server_pubkey),
        ClientCertSource::RawPublicKey {
            signing_key: other_signing,
        },
    )
    .unwrap();

    pump(&mut client, &mut server);

    assert!(!server.is_established());
    assert!(server.is_closed());
}
