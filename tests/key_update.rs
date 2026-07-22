mod common;

use common::{established_pair, pump};

#[test]
fn server_to_client_key_update_no_request_rotates_only_reader() {
    let (mut client, mut server) = established_pair();

    server.write_app(b"pre-update").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.pull_app().unwrap().as_slice(), b"pre-update");

    server.send_key_update(false).unwrap();
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
        server.send_key_update(false).unwrap();
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

    server.send_key_update(true).unwrap();
    pump(&mut client, &mut server);

    server.write_app(b"server-after").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.pull_app().unwrap().as_slice(), b"server-after");

    client.write_app(b"client-after").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(server.pull_app().unwrap().as_slice(), b"client-after");
}
