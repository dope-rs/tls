use crate::common::{ClientState, TestServer, mutual_server_state, pump, signing_key};
use dope_tls::{ClientAuth, ClientCertVerifier, ClientIdentity, Identity};

struct PinnedVerifier {
    expected_spki: Vec<u8>,
}

impl ClientCertVerifier for PinnedVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        identity.spki_der == self.expected_spki.as_slice()
    }
}

fn client_spki(pubkey: [u8; 32]) -> Vec<u8> {
    shin::identity::spki::SubjectPublicKey::Ed25519(pubkey)
        .encode()
        .unwrap()
}

fn server_config(signing: shin::crypto::sig::SigningKey) -> shin::server::config::Config {
    shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: signing,
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    }
}

fn client_config(server_pubkey: [u8; 32]) -> shin::client::config::Config {
    shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
}

fn server(
    config: shin::server::config::Config,
    verifier: PinnedVerifier,
) -> TestServer<
    shin::server::config::NoGuard,
    shin::server::config::ClientAuthVerifier<PinnedVerifier>,
> {
    let shard = shin::server::Shard::with_client_auth(config, ClientAuth::Required, verifier)
        .expect("mutual server shard");
    TestServer::new(mutual_server_state(shard).unwrap())
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
    let mut client = ClientState::mutual(
        client_config(server_pubkey),
        Identity::RawPublicKey {
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
    client.read_tcp(&server.pull_send()).expect("client read");
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
    let mut client = ClientState::new(client_config(server_pubkey)).unwrap();

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
    let mut client = ClientState::mutual(
        client_config(server_pubkey),
        Identity::RawPublicKey {
            signing_key: other_signing,
        },
    )
    .unwrap();

    pump(&mut client, &mut server);

    assert!(!server.is_established());
    assert!(server.is_closed());
}
