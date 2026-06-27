mod common;

use common::{established_pair, pump};

#[test]
fn server_to_client_key_update_no_request_rotates_only_reader() {
    let (mut client, mut server) = established_pair();

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
