pub mod common;

use common::native;

use std::io::{self, Read as _, Write as _};

#[test]
fn close_keeps_reads() {
    let (mut client, mut server) = native::try_half_closed().expect("native half-close");
    server.write_all(b"after close").expect("peer response");
    server.flush().expect("response output");
    let mut response = [0; 11];
    client.read_exact(&mut response).expect("response input");
    assert_eq!(&response, b"after close");
    assert!(client.conn.wants_read());
}

#[test]
#[ignore = "Rustls 0.23.46 asserts !sent_fatal_alert after local close_notify; run with --release --include-ignored"]
fn malformed_after_close() {
    let (mut client, mut server) = native::try_half_closed().expect("native half-close");
    server
        .sock
        .write_all(&[0xff, 3, 3, 0, 0])
        .expect("invalid peer record");
    let error = client.read(&mut [0; 1]).expect_err("invalid TLS record");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(matches!(
        error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidMessage(
            rustls::InvalidMessage::InvalidContentType
        ))
    ));
}
