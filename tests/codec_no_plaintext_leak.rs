mod common;

use common::raw_pair;

#[test]
fn tls_egress_produces_tls_record_not_plaintext() {
    let (client, _server) = raw_pair();
    let pending = client.pending_send_slice();
    assert!(!pending.is_empty(), "ClientHello must be emitted on init");
    assert_eq!(
        pending[0], 0x16,
        "first wire byte must be TLS handshake record (0x16)"
    );
    let plaintext = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    assert!(
        !pending.windows(plaintext.len()).any(|w| w == plaintext),
        "plaintext must not appear in handshake bytes"
    );
}

#[test]
fn tls_egress_handshake_then_app_record() {
    let (mut client, mut server) = raw_pair();

    let first = client.pending_send_slice().to_vec();
    let n = first.len();
    client.consume_pending_send(n);
    assert!(!first.is_empty(), "ClientHello must be emitted");
    assert_eq!(first[0], 0x16, "ClientHello is a handshake record (0x16)");

    let mut from_client = first;
    let mut steps = 0;
    while steps < 16 {
        steps += 1;
        if !from_client.is_empty() {
            server.read_tcp(&from_client).expect("server.read_tcp");
        }
        let from_server = server.pull_send();
        let progressed = !from_client.is_empty() || !from_server.is_empty();
        if !from_server.is_empty() {
            assert!(
                client.try_read_client_tcp(&from_server),
                "client.try_read_tcp"
            );
            while let Some(_chunk) = client.pull_app() {}
            let next = client.pending_send_slice().to_vec();
            let nn = next.len();
            client.consume_pending_send(nn);
            from_client = next;
        } else {
            from_client.clear();
        }
        if client.is_established() && server.is_established() {
            break;
        }
        if !progressed {
            break;
        }
    }

    assert!(client.is_established(), "client handshake should complete");
    assert!(server.is_established(), "server handshake should complete");

    let plaintext = b"hello-app-data";
    client.write_app(plaintext).expect("write_app");
    let app_wire = client.pending_send_slice().to_vec();
    let nn = app_wire.len();
    client.consume_pending_send(nn);
    assert!(!app_wire.is_empty(), "encrypted app data should be emitted");
    assert_eq!(
        app_wire[0], 0x17,
        "app data record must be 0x17 (application_data), got 0x{:02x}",
        app_wire[0]
    );
    assert!(
        !app_wire.windows(plaintext.len()).any(|w| w == plaintext),
        "plaintext must not appear in wire output"
    );
}
