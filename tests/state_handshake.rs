mod common;

use common::{established_pair, pump, raw_pair};
use dope_tls::Error;

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
    assert_eq!(&recv, b"GET / HTTP/1.1\r\nHost: example\r\n\r\n");
    assert!(server.pull_app().is_none());

    server.write_app(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    pump(&mut client, &mut server);
    let resp = client.pull_app().expect("client got app data");
    assert_eq!(&resp, b"HTTP/1.1 200 OK\r\n\r\n");
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
        got.extend_from_slice(&v);
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
