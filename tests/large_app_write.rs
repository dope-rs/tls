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

#[test]
fn large_app_write_fragments_without_panic() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
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
    assert!(client.is_established());
    assert!(server.is_established());

    let mut payload = vec![0u8; 50000];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    client.write_app(&payload).unwrap();
    let ciphertext = client.pull_send();
    assert!(!ciphertext.is_empty());

    let mut received = Vec::new();
    for chunk in ciphertext.chunks(8192) {
        server.read_tcp(chunk).expect("server.read_tcp");
        while let Some(app) = server.pull_app() {
            received.extend_from_slice(&app);
        }
    }
    while let Some(app) = server.pull_app() {
        received.extend_from_slice(&app);
    }

    assert_eq!(received, payload);
}

#[test]
fn oversized_app_write_backpressures_without_panic() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
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
    assert!(client.is_established());
    assert!(server.is_established());

    let mut payload = vec![0u8; 200_000];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let mut sent_plain = 0;
    let mut received = Vec::new();
    while sent_plain < payload.len() {
        let n = client.write_app(&payload[sent_plain..]).unwrap();
        assert!(n > 0 || !client.pending_send_slice().is_empty());
        sent_plain += n;
        let ciphertext = client.pull_send();
        server.read_tcp(&ciphertext).expect("server.read_tcp");
        while let Some(app) = server.pull_app() {
            received.extend_from_slice(&app);
        }
        if n == 0 {
            break;
        }
    }

    assert_eq!(sent_plain, payload.len());
    assert_eq!(received, payload);
}
