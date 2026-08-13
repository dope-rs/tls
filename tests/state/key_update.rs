use crate::common::{established_pair, pump};
use shin::wire::handshake::KeyUpdateRequest::{NotRequested, Requested};

#[test]
fn server_to_client_key_update_no_request_rotates_only_reader() {
    let (mut client, mut server) = established_pair();

    server.write_app(b"pre-update").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.pull_app().unwrap().as_slice(), b"pre-update");

    server.send_key_update(NotRequested).unwrap();
    pump(&mut client, &mut server);

    server.write_app(b"post-update").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.pull_app().unwrap().as_slice(), b"post-update");

    client.write_app(b"client-still-original").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(
        server.pull_app().unwrap().as_slice(),
        b"client-still-original"
    );
}

#[test]
fn many_key_updates_interleaved_with_app_data_do_not_trip_flood_cap() {
    let (mut client, mut server) = established_pair();

    for i in 0..12u8 {
        server.send_key_update(NotRequested).unwrap();
        pump(&mut client, &mut server);

        let msg = [b'a' + i];
        server.write_app(&msg).unwrap();
        pump(&mut client, &mut server);
        assert_eq!(client.pull_app().unwrap().as_slice(), msg);
    }

    client.write_app(b"client-alive").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(server.pull_app().unwrap().as_slice(), b"client-alive");
}

#[test]
fn server_to_client_key_update_with_request_rotates_both_directions() {
    let (mut client, mut server) = established_pair();

    server.send_key_update(Requested).unwrap();
    pump(&mut client, &mut server);

    server.write_app(b"server-after").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.pull_app().unwrap().as_slice(), b"server-after");

    client.write_app(b"client-after").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(server.pull_app().unwrap().as_slice(), b"client-after");
}

#[test]
fn pending_key_update_response_drains_after_a_full_low_level_cursor() {
    let (mut client, mut server) = established_pair();

    let queued = vec![0x5a; 32 * 1024];
    let consumed = client.write_app(&queued).unwrap();
    assert!(consumed < queued.len());
    let mut tail_records = 0;
    while client.write_app(b"12345").unwrap() == 5 {
        tail_records += 1;
    }
    assert_ne!(tail_records, 0);
    let full_len = client.pending_send_slice().len();

    server.send_key_update(Requested).unwrap();
    let requested = server.pull_send();
    client.read_tcp(&requested).unwrap();
    assert_eq!(
        client.pending_send_slice().len(),
        full_len,
        "the response remains semantic while the cursor has no spare capacity"
    );

    let application = client.pull_send();
    assert!(
        !client.pending_send_slice().is_empty(),
        "consuming the old ciphertext must drain the deferred response"
    );
    server.read_tcp(&application).unwrap();
    let response = client.pull_send();
    server.read_tcp(&response).unwrap();

    client.write_app(b"after-response").unwrap();
    pump(&mut client, &mut server);
    let mut last = None;
    while let Some(application) = server.pull_app() {
        last = Some(application);
    }
    assert_eq!(last.unwrap().as_slice(), b"after-response");
}
