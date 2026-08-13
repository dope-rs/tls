use crate::common::established_pair;
use dope_tls::Error;
use shin::wire::record;

#[test]
fn tampered_record_is_fatal_and_poisons_opener() {
    let (mut client, mut server) = established_pair();

    server.write_app(b"first").unwrap();
    let mut wire = server.pull_send();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    assert_eq!(
        client.read_tcp(&wire).unwrap_err(),
        Error::Record(record::Error::OpenFailed),
    );
    assert!(
        client.is_closed(),
        "decrypt failure must close the connection"
    );

    server.write_app(b"second").unwrap();
    let good = server.pull_send();
    let _ = client.read_tcp(&good);
    assert!(client.is_closed());
    assert!(client.pull_app().is_none());
}

#[test]
fn fatal_decrypt_emits_bad_record_mac_alert() {
    let (mut client, mut server) = established_pair();

    server.write_app(b"payload").unwrap();
    let mut wire = server.pull_send();
    let last = wire.len() - 1;
    wire[last] ^= 0xff;
    let _ = client.read_tcp(&wire);

    let alert = client.pull_send();
    assert!(!alert.is_empty(), "a fatal alert must be emitted");
    assert_eq!(
        alert[0], 23,
        "alert is sealed as application_data outer type"
    );
}
