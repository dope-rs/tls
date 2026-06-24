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
fn handshake_completes_in_process() {
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

    assert!(client.is_handshaking());
    assert!(server.is_handshaking());

    pump(&mut client, &mut server);

    assert!(client.is_established(), "client established");
    assert!(server.is_established(), "server established");
}

#[test]
fn application_data_round_trip() {
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

    client
        .write_app(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
        .unwrap();
    pump(&mut client, &mut server);
    let recv = server.pull_app().expect("server got app data");
    assert_eq!(&recv, b"GET / HTTP/1.1\r\nHost: example\r\n\r\n");
    assert!(server.pull_app().is_none());

    server.write_app(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    pump(&mut client, &mut server);
    let resp = client.pull_app().expect("client got app data");
    assert_eq!(&resp, b"HTTP/1.1 200 OK\r\n\r\n");
}

#[test]
fn close_notify_round_trip_closes_peer() {
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
    assert!(client.is_established() && server.is_established());

    client.send_close_notify().unwrap();
    assert!(client.is_closed());
    assert_eq!(
        client.write_app(b"too late").unwrap_err(),
        dope_tls::Error::NotEstablished,
    );
    pump(&mut client, &mut server);
    assert!(server.is_closed(), "server saw client's close_notify");
}

#[test]
fn close_notify_before_handshake_rejected() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
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
    assert!(client.is_handshaking());
    assert_eq!(
        client.send_close_notify().unwrap_err(),
        dope_tls::Error::NotEstablished,
    );
}

#[test]
fn close_notify_idempotent() {
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
    client.send_close_notify().unwrap();
    client.send_close_notify().unwrap();
}

#[test]
fn write_app_before_handshake_rejected() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
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
    assert!(client.is_handshaking());
    assert_eq!(
        client.write_app(b"too early").unwrap_err(),
        dope_tls::Error::NotEstablished
    );
}

#[test]
fn multiple_application_records_round_trip_in_order() {
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

    for i in 0..5u8 {
        client.write_app(&[i; 64]).unwrap();
    }
    pump(&mut client, &mut server);

    let mut expected = Vec::new();
    for i in 0..5u8 {
        expected.extend_from_slice(&[i; 64]);
    }
    let mut got = Vec::new();
    while let Some(v) = server.pull_app() {
        got.extend_from_slice(&v);
    }
    assert_eq!(got, expected);
    assert!(server.pull_app().is_none());
}

#[test]
fn fragmented_tcp_input_is_buffered_correctly() {
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

    let ch_bytes = client.pull_send();
    for chunk in ch_bytes.chunks(7) {
        server.read_tcp(chunk).unwrap();
    }

    let s_bytes = server.pull_send();
    for chunk in s_bytes.chunks(7) {
        client.read_tcp(chunk).unwrap();
    }

    let cf_bytes = client.pull_send();
    for chunk in cf_bytes.chunks(7) {
        server.read_tcp(chunk).unwrap();
    }

    assert!(client.is_established());
    assert!(server.is_established());
}
