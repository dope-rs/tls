use std::io::ErrorKind;

use dope::net::wire::RuntimeLimits;
use dope_tls::tls::endpoints;

const CONNECTIONS: usize = 1_024;
const RETAINED: usize = 4_096;
const MAX_RECORD: usize = 16_645;
const STAGING: usize = 24_837;

fn endpoint() -> endpoints::Configuration {
    endpoints::Configuration::server(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: super::common::signing_key(),
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

    assert_eq!(layout.recv_slots(), 65);
    assert_eq!(layout.send_slots(), 128);
    assert_eq!(layout.recv_capacity(), MAX_RECORD);
    assert_eq!(layout.send_capacity(), STAGING);
    assert_eq!(layout.payload_bytes(), 65 * MAX_RECORD + 128 * STAGING);
    assert_eq!(layout.payload_bytes(), 4_261_061);
}

#[test]
fn staged_and_ciphertext_budgets_are_independent_and_clamped() {
    let limits = RuntimeLimits::new(CONNECTIONS, RETAINED, 64 * 1024);
    let explicit = endpoint()
        .with_staged_record_budget(17)
        .with_ciphertext_budget(23)
        .buffer_layout(limits)
        .unwrap();
    assert_eq!(explicit.recv_slots(), 18);
    assert_eq!(explicit.send_slots(), 23);
    assert_eq!(explicit.payload_bytes(), 18 * MAX_RECORD + 23 * STAGING);

    let clamped = endpoint()
        .with_staged_record_budget(usize::MAX)
        .with_ciphertext_budget(usize::MAX)
        .buffer_layout(limits)
        .unwrap();
    assert_eq!(clamped.recv_slots(), CONNECTIONS + 1);
    assert_eq!(clamped.send_slots(), CONNECTIONS);
}

#[test]
fn zero_staged_retention_keeps_one_transient_cursor() {
    let staged = endpoint()
        .with_staged_record_budget(0)
        .buffer_layout(RuntimeLimits::new(CONNECTIONS, 0, 64 * 1024))
        .expect("the active record cursor remains available");
    assert_eq!(staged.recv_slots(), 1);
}

#[test]
fn zero_ciphertext_budget_and_layout_overflow_are_rejected() {
    let ciphertext = endpoint()
        .with_ciphertext_budget(0)
        .buffer_layout(RuntimeLimits::new(CONNECTIONS, 0, 64 * 1024))
        .expect_err("ciphertext progress requires at least one slot");
    assert_eq!(ciphertext.kind(), ErrorKind::InvalidInput);

    let error = endpoint()
        .with_staged_record_budget(usize::MAX)
        .buffer_layout(RuntimeLimits::new(usize::MAX, 0, 64 * 1024))
        .expect_err("the transient staged cursor must not wrap");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "TLS staged record slot overflow");
}
