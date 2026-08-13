use crate::common::established_pair;

#[test]
fn large_app_write_fragments_without_panic() {
    let (mut client, mut server) = established_pair();

    let mut payload = vec![0u8; 50000];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let mut sent_plain = 0;
    let mut received = Vec::new();
    while sent_plain < payload.len() {
        let n = client.write_app(&payload[sent_plain..]).unwrap();
        sent_plain += n;
        let ciphertext = client.pull_send();
        for chunk in ciphertext.chunks(8192) {
            server.read_tcp(chunk).expect("server.read_tcp");
            while let Some(app) = server.pull_app() {
                received.extend_from_slice(app.as_slice());
            }
        }
        assert!(
            n > 0 || !ciphertext.is_empty(),
            "no progress and nothing to drain: SEND_CAP too small for one record"
        );
    }
    while let Some(app) = server.pull_app() {
        received.extend_from_slice(app.as_slice());
    }

    assert_eq!(sent_plain, payload.len());
    assert_eq!(received, payload);
}

#[test]
fn oversized_app_write_backpressures_without_panic() {
    let (mut client, mut server) = established_pair();

    let mut payload = vec![0u8; 200_000];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let mut sent_plain = 0;
    let mut received = Vec::new();
    while sent_plain < payload.len() {
        let n = client.write_app(&payload[sent_plain..]).unwrap();
        assert!(n > 0 || !client.pending_send_slice().is_empty());
        sent_plain += n;
        let ciphertext = client.pull_send();
        server.read_tcp(&ciphertext).expect("server.read_tcp");
        while let Some(app) = server.pull_app() {
            received.extend_from_slice(app.as_slice());
        }
        if n == 0 {
            break;
        }
    }

    assert_eq!(sent_plain, payload.len());
    assert_eq!(received, payload);
}
