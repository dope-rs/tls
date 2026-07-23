use dope_net::wire::{OpenReservation, RuntimeLimits, Wire};
use dope_tls::tls::{Endpoint, OnceClient, Standard, Tls};

type ClientTls = Tls<Standard, OnceClient>;

fn client_config() -> shin::client::Config {
    shin::client::Config {
        verifier: shin::client::Verifier::RawPublicKey {
            expected_pubkey: [9; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    }
}

#[test]
fn cancelled_open_preserves_once_client_setup() {
    let endpoint: Endpoint<Standard, OnceClient> = Endpoint::client(client_config());
    let mut runtime =
        ClientTls::runtime_context(RuntimeLimits::new(1, 0, 64 * 1024), endpoint).unwrap();

    drop(ClientTls::prepare_open(&mut runtime).unwrap());

    let (_wire, _send) = ClientTls::prepare_open(&mut runtime).unwrap().commit();
    assert!(ClientTls::prepare_open(&mut runtime).is_none());
}
