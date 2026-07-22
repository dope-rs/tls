mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::{pump, signing_key};
use dope_tls::{ClientAuth, ClientCertSource, ClientCertVerifier, ClientIdentity, state::State};

const CERT_TYPE_RAW_PUBLIC_KEY: u8 = 2;

#[derive(Default)]
struct Seen {
    cert_type: u8,
    spki_der: Vec<u8>,
    calls: u32,
}

struct PinnedVerifier {
    expected_spki: Vec<u8>,
    seen: RefCell<Seen>,
}

impl ClientCertVerifier for PinnedVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        let mut seen = self.seen.borrow_mut();
        seen.cert_type = identity.cert_type;
        seen.spki_der = identity.spki_der.to_vec();
        seen.calls += 1;
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
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_keys: None,
        accept_early_data: false,
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

fn round_trip(sender: &mut State, receiver: &mut State, msg: &[u8]) {
    sender.write_app(msg).unwrap();
    let wire = sender.pull_send();
    receiver.read_tcp(&wire).unwrap();
    assert_eq!(receiver.pull_app().unwrap().as_slice(), msg);
}

#[test]
fn required_client_auth_completes_and_pins_spki() {
    let server_signing = signing_key();
    let server_pubkey = *server_signing.pubkey().unwrap();

    let client_signing = signing_key();
    let client_pubkey = *client_signing.pubkey().unwrap();
    let expected_spki = client_spki(client_pubkey);

    let verifier = Rc::new(PinnedVerifier {
        expected_spki: expected_spki.clone(),
        seen: RefCell::new(Seen::default()),
    });

    let mut server = State::new_server_mutual(
        server_config(server_signing),
        ClientAuth::Required,
        verifier.clone(),
    )
    .expect("valid server buffer layout");
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

    let seen = verifier.seen.borrow();
    assert_eq!(seen.calls, 1, "verifier must be invoked exactly once");
    assert_eq!(seen.cert_type, CERT_TYPE_RAW_PUBLIC_KEY);
    assert_eq!(
        seen.spki_der, expected_spki,
        "verifier saw the client's SPKI"
    );
    drop(seen);

    round_trip(&mut client, &mut server, b"client to server");
    round_trip(&mut server, &mut client, b"server to client");
}

#[test]
fn required_server_rejects_anonymous_client() {
    let server_signing = signing_key();
    let server_pubkey = *server_signing.pubkey().unwrap();

    let verifier = Rc::new(PinnedVerifier {
        expected_spki: vec![0u8; 44],
        seen: RefCell::new(Seen::default()),
    });

    let mut server = State::new_server_mutual(
        server_config(server_signing),
        ClientAuth::Required,
        verifier.clone(),
    )
    .expect("valid server buffer layout");
    let mut client = State::new_client(client_config(server_pubkey)).unwrap();

    pump(&mut client, &mut server);

    assert!(
        !server.is_established(),
        "Required server must reject an anonymous client"
    );
    assert!(server.is_closed());
    assert_eq!(
        verifier.seen.borrow().calls,
        0,
        "verifier is never reached for an empty client Certificate"
    );
}

#[test]
fn required_server_rejects_unauthorized_client() {
    let server_signing = signing_key();
    let server_pubkey = *server_signing.pubkey().unwrap();

    let authorized_signing = signing_key();
    let authorized_pubkey = *authorized_signing.pubkey().unwrap();
    let expected_spki = client_spki(authorized_pubkey);

    let verifier = Rc::new(PinnedVerifier {
        expected_spki,
        seen: RefCell::new(Seen::default()),
    });

    let mut server = State::new_server_mutual(
        server_config(server_signing),
        ClientAuth::Required,
        verifier.clone(),
    )
    .expect("valid server buffer layout");

    let other_signing = signing_key();
    let mut client = State::new_client_mutual(
        client_config(server_pubkey),
        ClientCertSource::RawPublicKey {
            signing_key: other_signing,
        },
    )
    .unwrap();

    pump(&mut client, &mut server);

    assert!(
        !server.is_established(),
        "Required server must reject an unpinned client identity"
    );
    assert!(server.is_closed());
    assert_eq!(
        verifier.seen.borrow().calls,
        1,
        "verifier must be consulted and reject the unauthorized identity"
    );
}
