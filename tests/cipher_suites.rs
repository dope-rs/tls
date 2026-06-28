mod common;

use common::{pump, raw_pair_with_suites};
use shin::record::CipherSuite;

fn negotiates(suite: CipherSuite) {
    let (mut client, mut server) = raw_pair_with_suites(&[suite]);
    pump(&mut client, &mut server);

    assert!(
        client.is_established(),
        "client established under {suite:?}"
    );
    assert!(
        server.is_established(),
        "server established under {suite:?}"
    );

    client.write_app(b"ping").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(server.pull_app().as_deref(), Some(&b"ping"[..]));

    server.write_app(b"pong").unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.pull_app().as_deref(), Some(&b"pong"[..]));
}

#[test]
fn aes256_sha384_round_trip() {
    negotiates(CipherSuite::Aes256GcmSha384);
}

#[test]
fn chacha20_sha256_round_trip() {
    negotiates(CipherSuite::ChaCha20Poly1305Sha256);
}

#[test]
fn aes128_sha256_round_trip() {
    negotiates(CipherSuite::Aes128GcmSha256);
}
