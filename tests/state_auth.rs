pub mod common;

use std::{net::Ipv4Addr, sync::Arc};

use common::native;
use dope_tls::config::raw::Identity;
use rustls::{CertificateError, ClientConnection, Connection, PeerIncompatible, ServerConnection};

#[test]
fn required_auth_completes() {
    let server = Identity::from_seed(&[1; 32]).expect("server key");
    let client = Identity::from_seed(&[2; 32]).expect("client key");
    let pin = server.public_key();
    let server = Arc::new(
        server
            .server_auth(client.public_key())
            .expect("mutual server config"),
    );
    let client = Arc::new(client.mutual(pin).expect("mutual client config"));
    let mut client = Connection::Client(
        ClientConnection::new(client, Ipv4Addr::LOCALHOST.into()).expect("client"),
    );
    let mut server = Connection::Server(ServerConnection::new(server).expect("server"));

    native::pump(&mut client, &mut server).expect("mutual handshake");
    assert!(!client.is_handshaking() && !server.is_handshaking());
}

#[test]
fn anonymous_is_rejected() {
    let identity = Identity::from_seed(&[1; 32]).expect("server key");
    let required = Identity::from_seed(&[2; 32]).expect("required client key");
    let client = Arc::new(Identity::client(identity.public_key()).expect("client config"));
    let server = Arc::new(
        identity
            .server_auth(required.public_key())
            .expect("mutual server config"),
    );
    let mut client = Connection::Client(
        ClientConnection::new(client, Ipv4Addr::LOCALHOST.into()).expect("client"),
    );
    let mut server = Connection::Server(ServerConnection::new(server).expect("server"));

    assert!(matches!(
        native::pump(&mut client, &mut server),
        Err(native::Error::Tls(rustls::Error::PeerIncompatible(
            PeerIncompatible::IncorrectCertificateTypeExtension
        )))
    ));
}

#[test]
fn client_pin_is_rejected() {
    let identity = Identity::from_seed(&[1; 32]).expect("server key");
    let required = Identity::from_seed(&[2; 32]).expect("required client key");
    let other = Identity::from_seed(&[3; 32]).expect("other client key");
    let client = Arc::new(
        other
            .mutual(identity.public_key())
            .expect("mutual client config"),
    );
    let server = Arc::new(
        identity
            .server_auth(required.public_key())
            .expect("mutual server config"),
    );
    let mut client = Connection::Client(
        ClientConnection::new(client, Ipv4Addr::LOCALHOST.into()).expect("client"),
    );
    let mut server = Connection::Server(ServerConnection::new(server).expect("server"));

    assert!(matches!(
        native::pump(&mut client, &mut server),
        Err(native::Error::Tls(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure
        )))
    ));
}

#[test]
fn server_pin_is_rejected() {
    let identity = Identity::from_seed(&[1; 32]).expect("server key");
    let required = Identity::from_seed(&[2; 32]).expect("required server key");
    let client = Arc::new(Identity::client(required.public_key()).expect("client config"));
    let server = Arc::new(identity.server().expect("server config"));
    let mut client = Connection::Client(
        ClientConnection::new(client, Ipv4Addr::LOCALHOST.into()).expect("client"),
    );
    let mut server = Connection::Server(ServerConnection::new(server).expect("server"));

    assert!(matches!(
        native::pump(&mut client, &mut server),
        Err(native::Error::Tls(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure
        )))
    ));
}
