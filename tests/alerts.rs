mod common;

use common::{established_pair, raw_client, signing_key};
use dope_tls::{error::Error, state::status::PeerClose};
use shin::alert::{Alert, AlertDescription};

#[test]
fn close_notify_is_a_clean_close_not_an_error() {
    let (mut client, mut server) = established_pair();
    client.send_close_notify().unwrap();
    let wire = client.pull_send();
    server
        .read_tcp(&wire)
        .expect("close_notify is not an error");
    assert!(server.is_closed());
    assert_eq!(server.peer_close(), PeerClose::CloseNotify);
}

#[test]
fn fatal_alert_surfaces_description_and_closes() {
    let (mut client, mut server) = established_pair();
    server
        .send_fatal_alert(AlertDescription::HandshakeFailure)
        .unwrap();
    let wire = server.pull_send();
    let err = client.read_tcp(&wire).unwrap_err();
    assert_eq!(err, Error::PeerAlert(AlertDescription::HandshakeFailure));
    assert_eq!(
        client.peer_close(),
        PeerClose::Fatal(AlertDescription::HandshakeFailure)
    );
    assert!(client.is_closed());
}

#[test]
fn eof_without_close_notify_is_truncation() {
    let (client, mut server) = established_pair();
    drop(client);
    assert_eq!(server.peer_eof().unwrap_err(), Error::Truncated);
    assert_eq!(server.peer_close(), PeerClose::Truncated);
    assert!(server.is_closed());
}

#[test]
fn eof_after_close_notify_is_clean() {
    let (mut client, mut server) = established_pair();
    client.send_close_notify().unwrap();
    let wire = client.pull_send();
    server.read_tcp(&wire).unwrap();
    server.peer_eof().unwrap();
    assert_eq!(server.peer_close(), PeerClose::CloseNotify);
}

#[test]
fn peer_close_notify_can_still_be_echoed() {
    let (mut client, mut server) = established_pair();
    client.send_close_notify().unwrap();
    server.read_tcp(&client.pull_send()).unwrap();
    assert_eq!(server.peer_close(), PeerClose::CloseNotify);
    assert!(server.is_closed());

    server
        .send_close_notify()
        .expect("a peer-initiated close_notify can still be echoed back");
    assert!(
        !server.pull_send().is_empty(),
        "the echoed close_notify must reach the wire before our FIN"
    );
}

#[test]
fn malformed_plaintext_alert_is_fatal() {
    let server_pubkey = *signing_key().pubkey().unwrap();
    let mut client = raw_client(server_pubkey);
    let _ = client.pull_send();
    let rec = [21u8, 0x03, 0x03, 0x00, 0x01, 0x01];
    assert_eq!(client.read_tcp(&rec).unwrap_err(), Error::MalformedAlert);
    assert!(client.is_closed());
}

#[test]
fn plaintext_close_notify_is_rejected_not_clean() {
    let server_pubkey = *signing_key().pubkey().unwrap();
    let mut client = raw_client(server_pubkey);
    let _ = client.pull_send();
    let rec = [21u8, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
    assert_eq!(
        client.read_tcp(&rec).unwrap_err(),
        Error::PeerAlert(AlertDescription::CloseNotify)
    );
    assert_eq!(
        client.peer_close(),
        PeerClose::Fatal(AlertDescription::CloseNotify)
    );
    assert!(client.is_closed());
}

#[test]
fn alert_body_matches_shin_encoding() {
    assert_eq!(
        Alert::fatal(AlertDescription::HandshakeFailure).body(),
        [2, 40]
    );
    assert_eq!(Alert::close_notify().body(), [1, 0]);
}
