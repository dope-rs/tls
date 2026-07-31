mod common;

use dope_net::wire::RuntimeLimits;
use dope_tls::tls::Endpoint;

const CONNECTIONS: usize = 1_024;
const RETAINED: usize = 4_096;
const MAX_RECORD: usize = 16_645;
const STAGING: usize = 24_837;

fn endpoint() -> Endpoint {
    Endpoint::server(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: common::signing_key(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap()
}

#[test]
fn default_layout_has_an_exact_linear_payload_bound() {
    let limits = RuntimeLimits::new(CONNECTIONS, RETAINED, 64 * 1024);
    let layout = endpoint().buffer_layout(limits).unwrap();

    assert_eq!(layout.recv_slots(), CONNECTIONS + RETAINED);
    assert_eq!(layout.pending_slots(), CONNECTIONS);
    assert_eq!(layout.send_slots(), CONNECTIONS);
    assert_eq!(layout.recv_capacity(), MAX_RECORD);
    assert_eq!(layout.pending_capacity(), STAGING);
    assert_eq!(layout.send_capacity(), STAGING);
    assert_eq!(
        layout.payload_bytes(),
        (CONNECTIONS + RETAINED) * MAX_RECORD + 2 * CONNECTIONS * STAGING
    );
    assert_eq!(layout.payload_bytes(), 136_088_576);

    let previous_payload_bytes = STAGING * (3 * CONNECTIONS + RETAINED + 1);
    assert_eq!(previous_payload_bytes, 178_056_453);
    assert!(layout.payload_bytes() < previous_payload_bytes);
}

#[test]
fn receive_credit_bounds_default_fragment_retention_to_one_per_connection() {
    let limits = RuntimeLimits::new(CONNECTIONS, RETAINED, 64 * 1024).with_recv_credit();
    let layout = endpoint().buffer_layout(limits).unwrap();

    assert_eq!(layout.recv_slots(), 2 * CONNECTIONS);
    assert_eq!(layout.pending_slots(), CONNECTIONS);
    assert_eq!(layout.send_slots(), CONNECTIONS);
    assert_eq!(layout.payload_bytes(), 84_955_136);
}

#[test]
fn retained_fragment_budget_is_explicit_and_clamped_to_runtime_limit() {
    let limits = RuntimeLimits::new(CONNECTIONS, RETAINED, 64 * 1024);
    let none = endpoint()
        .with_retained_fragment_budget(0)
        .buffer_layout(limits)
        .unwrap();
    assert_eq!(none.recv_slots(), CONNECTIONS);
    assert_eq!(none.payload_bytes(), 67_910_656);

    let one_per_connection = endpoint()
        .with_retained_fragment_budget(CONNECTIONS)
        .buffer_layout(limits)
        .unwrap();
    assert_eq!(one_per_connection.recv_slots(), 2 * CONNECTIONS);
    assert_eq!(one_per_connection.payload_bytes(), 84_955_136);

    let maximum = endpoint()
        .with_retained_fragment_budget(usize::MAX)
        .buffer_layout(limits)
        .unwrap();
    assert_eq!(maximum.recv_slots(), CONNECTIONS + RETAINED);
    assert_eq!(maximum.payload_bytes(), 136_088_576);
}
