use crate::common::{
    ClientState, TestServer, established_pair, pump, raw_client, raw_pair, server_state,
    signing_key,
};
use dope_tls::{
    Error,
    state::{api::capabilities::Status, status::Read},
    tls::{endpoints, roles},
};
use shin::wire::record::HEADER_LEN;

fn pooled_established_pair() -> (ClientState, TestServer) {
    established_pair()
}

#[test]
fn invalid_server_config_is_rejected_before_handshake() {
    let error = endpoints::Configuration::<roles::Server>::server(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: signing_key(),
        },
        alpn_protocols: vec![Vec::new()],
        ticket_keys: None,
    })
    .err()
    .expect("invalid server configuration");
    assert_eq!(error, Error::Handshake(shin::connection::Error::BadConfig));
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
fn pooled_server_preserves_negotiated_alpn_without_borrowing_its_shard() {
    let signing = signing_key();
    let server_pubkey = *signing.pubkey().unwrap();
    let mut client = ClientState::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: vec![b"http/1.1".to_vec(), b"h2".to_vec()],
        enable_early_data: false,
    })
    .unwrap();
    let shard = shin::server::Shard::new(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: signing,
        },
        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        ticket_keys: None,
    })
    .unwrap();
    let state = server_state(shard).expect("pooled server");
    let mut server = TestServer::new(state);

    pump(&mut client, &mut server);

    assert_eq!(Status::selected_alpn(&*client), Some(b"h2".as_slice()));
    assert_eq!(Status::selected_alpn(&*server), Some(b"h2".as_slice()));
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
fn complete_records_are_returned_as_input_ranges() {
    let (mut client, mut server) = established_pair();
    let expected = [
        b"first".as_slice(),
        b"second".as_slice(),
        b"third".as_slice(),
    ];
    for plaintext in expected {
        assert_eq!(client.write_app(plaintext).expect("seal"), plaintext.len());
    }
    let mut wire = client.pull_send();
    let base = wire.as_ptr().addr();
    let end = base + wire.len();

    let read = server.read_tcp_in_place(&mut wire);
    assert_eq!(read.status(), Read::Continue);
    let chunks = read.into_plain();
    assert_eq!(chunks.len(), expected.len());
    for (chunk, expected) in chunks.zip(expected) {
        let start = chunk.as_ptr().addr();
        assert!(
            start >= base && start + chunk.len() <= end,
            "plaintext must alias the provided ciphertext buffer"
        );
        assert_eq!(chunk, expected);
    }
    assert!(server.pull_app().is_none());
}

#[test]
fn fragmented_record_returns_the_decrypted_staging_range() {
    let (mut client, mut server) = pooled_established_pair();

    let expected = vec![0x5a; 12_000];
    assert_eq!(client.write_app(&expected).expect("seal"), expected.len());
    let mut wire = client.pull_send();
    let split = 7;

    let read = server.read_tcp_in_place(&mut wire[..split]);
    assert_eq!(read.status(), Read::Stop);
    assert_eq!(read.into_plain().len(), 0);
    let staged = server.staged_recv().as_ptr().addr();

    let read = server.read_staged_wire(&wire[split..]);
    assert_eq!(read.status(), Read::Continue);
    let consumed = read.consumed();
    assert_eq!(consumed, wire.len() - split);
    let chunk = read.into_chunk().expect("fragmented application record");
    assert_eq!(
        chunk.as_slice().as_ptr().addr(),
        staged + HEADER_LEN,
        "plaintext must remain in the staging lease"
    );
    assert_eq!(chunk.as_slice(), expected);
    drop(chunk);
    assert!(
        !server.has_staged_recv(),
        "replacement staging must be empty"
    );
}

#[test]
fn every_application_record_split_uses_the_same_record_semantics() {
    let (mut client, mut server) = pooled_established_pair();
    let expected = [0x5a; 96];
    assert_eq!(client.write_app(&expected).expect("seal"), expected.len());
    let mut wire = client.pull_send();
    let record_len = wire.len();

    for split in 1..record_len {
        if split != 1 {
            assert_eq!(client.write_app(&expected).expect("seal"), expected.len());
            wire = client.pull_send();
            assert_eq!(wire.len(), record_len);
        }
        {
            let read = server.read_tcp_in_place(&mut wire[..split]);
            assert_eq!(
                read.status(),
                Read::Stop,
                "direct prefix failed at split {split}"
            );
            assert_eq!(
                read.into_plain().len(),
                0,
                "incomplete record escaped at split {split}"
            );
        }
        let read = server.read_staged_wire(&wire[split..]);
        assert_eq!(
            read.status(),
            Read::Continue,
            "staged suffix failed at split {split}"
        );
        let consumed = read.consumed();
        assert_eq!(consumed, record_len - split);
        assert_eq!(
            read.into_chunk().expect("application chunk").as_slice(),
            expected,
            "plaintext changed at split {split}"
        );
        assert!(
            !server.has_staged_recv(),
            "staging was not replaced at split {split}"
        );
    }
}

#[test]
fn malformed_control_record_has_identical_fragmented_state() {
    let server_pubkey = *signing_key().pubkey().expect("server public key");
    let mut direct = raw_client(server_pubkey);
    let mut staged = raw_client(server_pubkey);
    let _ = direct.pull_send();
    let _ = staged.pull_send();
    let record = [21u8, 0x03, 0x03, 0x00, 0x01, 0x01];

    let mut direct_record = record;
    let direct_read = direct.read_tcp_in_place(&mut direct_record);
    assert_eq!(direct_read.status(), Read::Failed);

    let mut staged_record = record;
    let prefix = staged.read_tcp_in_place(&mut staged_record[..3]);
    assert_eq!(prefix.status(), Read::Stop);
    let read = staged.read_staged_wire(&staged_record[3..]);
    assert_eq!(read.consumed(), record.len() - 3);
    assert_eq!(read.status(), Read::Failed);
    assert!(read.into_chunk().is_none());

    assert_eq!(direct.phase(), staged.phase());
    assert_eq!(direct.peer_close(), staged.peer_close());
    assert!(direct.is_closed() && staged.is_closed());
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
