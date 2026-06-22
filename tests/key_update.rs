use dope_tls::State;
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    SigningKey::from_seed(&seed).unwrap()
}

fn pump(client: &mut State, server: &mut State) {
    for _ in 0..10 {
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

fn established_pair() -> (State, State) {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey();
    let mut server = State::new_server(shin::server::Config {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = State::new_client(shin::client::Config {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap();
    pump(&mut client, &mut server);
    assert!(client.is_established() && server.is_established());
    (client, server)
}

#[test]
fn server_to_client_key_update_no_request_rotates_only_reader() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey();
    let mut server = State::new_server(shin::server::Config {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: signing,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        ticket_secret: None,
        accept_early_data: false,
    });
    let mut client = State::new_client(shin::client::Config {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap();
    pump(&mut client, &mut server);
    assert!(client.is_established() && server.is_established());

    server.write_app(b"pre-update").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(&client.pull_app().unwrap(), b"pre-update");

    server.send_key_update(false).unwrap();
    pump(&mut client, &mut server);

    server.write_app(b"post-update").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(&client.pull_app().unwrap(), b"post-update");

    client.write_app(b"client-still-original").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(&server.pull_app().unwrap(), b"client-still-original");
}

#[test]
fn server_to_client_key_update_with_request_rotates_both_directions() {
    let (mut client, mut server) = established_pair();

    server.send_key_update(true).unwrap();
    pump(&mut client, &mut server);

    server.write_app(b"server-after").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(&client.pull_app().unwrap(), b"server-after");

    client.write_app(b"client-after").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(&server.pull_app().unwrap(), b"client-after");
}
