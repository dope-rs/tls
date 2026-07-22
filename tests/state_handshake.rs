mod common;

use common::{established_pair, pump, raw_pair, signing_key};
use dope_tls::{error::Error, state::State};

#[test]
fn invalid_server_config_is_rejected_before_handshake() {
    let error = State::new_server(shin::server::Config {
        source: shin::server::CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![Vec::new()],
        ticket_keys: None,
        accept_early_data: false,
    })
    .err()
    .expect("invalid server configuration");
    assert_eq!(error, Error::Handshake(shin::Error::BadConfig));
}

#[test]
fn handshake_completes_in_process() {
    let (mut client, mut server) = raw_pair();
    assert!(client.is_handshaking());
    assert!(server.is_handshaking());

    pump(&mut client, &mut server);

    assert!(client.is_established(), "client established");
    assert!(server.is_established(), "server established");
}

#[test]
fn application_data_round_trip() {
    let (mut client, mut server) = established_pair();

    client
        .write_app(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
        .unwrap();
    pump(&mut client, &mut server);
    let recv = server.pull_app().expect("server got app data");
    assert_eq!(recv.as_slice(), b"GET / HTTP/1.1\r\nHost: example\r\n\r\n");
    assert!(server.pull_app().is_none());

    server.write_app(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    pump(&mut client, &mut server);
    let resp = client.pull_app().expect("client got app data");
    assert_eq!(resp.as_slice(), b"HTTP/1.1 200 OK\r\n\r\n");
}

#[test]
fn pulled_application_data_does_not_block_later_reads() {
    let (mut client, mut server) = raw_pair();
    pump(&mut client, &mut server);

    client.write_app(b"first").unwrap();
    server.read_tcp(&client.pull_send()).unwrap();
    let first = server.pull_app().expect("first application data");

    client.write_app(b"second").unwrap();
    server.read_tcp(&client.pull_send()).unwrap();
    let second = server.pull_app().expect("second application data");

    assert_eq!(first, b"first");
    assert_eq!(second, b"second");
}

#[test]
fn close_notify_round_trip_closes_peer() {
    let (mut client, mut server) = established_pair();

    client.send_close_notify().unwrap();
    assert!(client.is_closed());
    assert_eq!(
        client.write_app(b"too late").unwrap_err(),
        Error::NotEstablished,
    );
    pump(&mut client, &mut server);
    assert!(server.is_closed(), "server saw client's close_notify");
}

#[test]
fn close_notify_before_handshake_rejected() {
    let (mut client, _server) = raw_pair();
    assert!(client.is_handshaking());
    assert_eq!(
        client.send_close_notify().unwrap_err(),
        Error::NotEstablished,
    );
}

#[test]
fn close_notify_idempotent() {
    let (mut client, _server) = established_pair();
    client.send_close_notify().unwrap();
    client.send_close_notify().unwrap();
}

#[test]
fn write_app_before_handshake_rejected() {
    let (mut client, _server) = raw_pair();
    assert!(client.is_handshaking());
    assert_eq!(
        client.write_app(b"too early").unwrap_err(),
        Error::NotEstablished
    );
}

#[test]
fn multiple_application_records_round_trip_in_order() {
    let (mut client, mut server) = established_pair();

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
        got.extend_from_slice(v.as_slice());
    }
    assert_eq!(got, expected);
    assert!(server.pull_app().is_none());
}

#[test]
fn fragmented_tcp_input_is_buffered_correctly() {
    let (mut client, mut server) = raw_pair();

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

#[test]
fn handshake_message_spanning_plaintext_records_completes() {
    let (mut client, mut server) = raw_pair();
    let client_hello = client.pull_send();
    let body_len = u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize;
    assert_eq!(client_hello.len(), 5 + body_len);

    let split = 9.min(body_len - 1);
    let mut first = client_hello[..5].to_vec();
    first[3..5].copy_from_slice(&(split as u16).to_be_bytes());
    first.extend_from_slice(&client_hello[5..5 + split]);

    let remaining = body_len - split;
    let mut second = client_hello[..5].to_vec();
    second[3..5].copy_from_slice(&(remaining as u16).to_be_bytes());
    second.extend_from_slice(&client_hello[5 + split..]);

    server.read_tcp(&first).unwrap();
    assert!(server.pending_send_slice().is_empty());
    server.read_tcp(&second).unwrap();
    pump(&mut client, &mut server);

    assert!(client.is_established());
    assert!(server.is_established());
}
