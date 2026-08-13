use dope::net::wire::{OpenReservation, RuntimeLimits, Wire};
use dope_tls::state::State;
use dope_tls::state::api::{
    self,
    capabilities::{Status, Write},
};
use dope_tls::state::sessions::{clients, servers};
use dope_tls::state::status::Read;
use dope_tls::tls::{self, ClientPlan, endpoints, roles};
use dope_tls::{ClientAuth, ClientCertVerifier, ClientIdentity, Identity};
use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ED25519};
use shin::crypto::sig::SigningKey;
use shin::identity::asn1::{Reader, Tag};
use shin::server::Shard;
use shin::server::config::{CertSource, ClientAuthVerifier, Config, NoGuard};

mod allocation;

use allocation::measured;

fn client_config(expected_pubkey: [u8; 32]) -> shin::client::config::Config {
    shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey { expected_pubkey },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
}

fn large_x509_config(extension_len: usize) -> Config {
    large_x509_identity(extension_len).0
}

fn large_x509_identity(extension_len: usize) -> (Config, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let encoded_key = key.serialize_der();
    let mut outer = Reader::new(&encoded_key);
    let mut key_info = Reader::new(outer.read_tagged(Tag::SEQUENCE).unwrap());
    key_info.read_uint().unwrap();
    key_info.read_tagged(Tag::SEQUENCE).unwrap();
    let mut private_key = Reader::new(key_info.read_tagged(Tag::OCTET_STRING).unwrap());
    let seed: [u8; 32] = private_key
        .read_tagged(Tag::OCTET_STRING)
        .unwrap()
        .try_into()
        .unwrap();
    let mut params = CertificateParams::new(vec!["large.local".into()]).unwrap();
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 1],
            vec![0xA5; extension_len],
        ));
    let certificate = params.self_signed(&key).unwrap().der().to_vec();

    (
        Config {
            source: CertSource::X509 {
                chain_der: vec![certificate.clone()],
                signing_key: SigningKey::from_seed(&seed).unwrap(),
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        certificate,
    )
}

#[test]
fn low_level_state_obeys_and_recycles_session_capacity() {
    type ClientTls = tls::Tls<roles::Client>;

    let plan = ClientPlan::new(client_config([7; 32])).unwrap();
    let storage = endpoints::SessionStorage::<roles::Client>::try_with_capacity(1).unwrap();
    let mut runtime = ClientTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        endpoints::Configuration::from_plan(plan).bind(&storage),
    )
    .unwrap();

    let first = runtime.open_state().unwrap().unwrap();
    let (saturated, allocations) = measured(|| runtime.open_state());
    assert!(matches!(saturated, Ok(None)));
    assert_eq!(allocations, 0);

    drop(first);
    runtime
        .open_state()
        .unwrap()
        .expect("dropping a state must return its session slot");
}

#[test]
fn bound_low_level_client_pools_open_without_allocating() {
    type ClientTls = tls::Tls<roles::Client>;

    assert_eq!(
        std::mem::size_of::<clients::Pooled<'static>>(),
        2 * std::mem::size_of::<usize>(),
    );

    let standard = ClientPlan::new(client_config([7; 32])).unwrap();
    let mutual = ClientPlan::mutual(
        client_config([7; 32]),
        shin::client::config::Identity::RawPublicKey {
            signing_key: SigningKey::from_seed(&[13; 32]).unwrap(),
        },
    )
    .unwrap();
    let standard_storage =
        endpoints::SessionStorage::<roles::Client>::try_with_capacity(2).unwrap();
    let mutual_storage = endpoints::SessionStorage::<roles::Client>::try_with_capacity(1).unwrap();
    let mut standard = ClientTls::runtime_context::<0>(
        RuntimeLimits::new(2, 0, 64 * 1024),
        endpoints::Configuration::from_plan(standard).bind(&standard_storage),
    )
    .unwrap();
    let mut mutual = ClientTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        endpoints::Configuration::from_plan(mutual).bind(&mutual_storage),
    )
    .unwrap();

    let (_, allocations) = measured(|| {
        let first = standard.open_state().unwrap().unwrap();
        let second = standard.open_state().unwrap().unwrap();
        drop((first, second));

        for _ in 0..128 {
            drop(standard.open_state().unwrap().unwrap());
            drop(mutual.open_state().unwrap().unwrap());
        }
    });

    assert_eq!(allocations, 0);
}

#[test]
fn pooled_sessions_cancel_and_reopen_without_allocating() {
    type ClientTls = tls::Tls<roles::Client>;
    type ServerTls = tls::Tls;

    let client_storage = ClientTls::connection_storage::<0>(1).unwrap();
    let client_endpoint = endpoints::Configuration::client(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: [7; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    })
    .unwrap();
    let mut client_runtime = ClientTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        client_endpoint.bind(&client_storage),
    )
    .unwrap();

    let server_storage = ServerTls::connection_storage::<0>(1).unwrap();
    let server_endpoint = endpoints::Configuration::server(Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[7; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let mut server_runtime = ServerTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        server_endpoint.bind(&server_storage),
    )
    .unwrap();

    let (_, allocations) = measured(|| {
        for _ in 0..128 {
            drop(ClientTls::prepare_open::<0>(&mut client_runtime).unwrap());
            drop(ServerTls::prepare_open::<0>(&mut server_runtime).unwrap());
        }
        for _ in 0..128 {
            let client = ClientTls::prepare_open::<0>(&mut client_runtime)
                .unwrap()
                .unwrap()
                .commit();
            let server = ServerTls::prepare_open::<0>(&mut server_runtime)
                .unwrap()
                .unwrap()
                .commit();
            drop((client, server));
        }
    });

    assert_eq!(allocations, 0);
}

#[test]
fn server_pool_reserves_the_shard_layout_once_then_opens_without_allocating() {
    type ServerTls = tls::Tls;

    let storage = ServerTls::connection_storage::<0>(2).unwrap();
    let endpoint = endpoints::Configuration::server(Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[31; 32]).unwrap(),
        },
        alpn_protocols: vec![vec![0x61; 200]],
        ticket_keys: None,
    })
    .unwrap();

    let (mut runtime, initialization_allocations) = measured(|| {
        ServerTls::runtime_context::<0>(
            RuntimeLimits::new(2, 0, 64 * 1024),
            endpoint.bind(&storage),
        )
        .unwrap()
    });
    assert!(initialization_allocations > 0);

    let (_, open_allocations) = measured(|| {
        for _ in 0..128 {
            drop(ServerTls::prepare_open::<0>(&mut runtime).unwrap());
        }
    });
    assert_eq!(open_allocations, 0);
}

#[test]
fn server_storage_lifetime_keeps_its_first_exact_layout() {
    type ServerTls = tls::Tls;

    let storage = endpoints::SessionStorage::<roles::Server>::try_with_capacity(1).unwrap();
    let small = endpoints::Configuration::server(Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[32; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let runtime =
        ServerTls::runtime_context::<0>(RuntimeLimits::new(1, 0, 64 * 1024), small.bind(&storage))
            .unwrap();
    drop(runtime);

    let large = endpoints::Configuration::server(large_x509_config(32 * 1024)).unwrap();
    assert!(
        ServerTls::runtime_context::<0>(RuntimeLimits::new(1, 0, 64 * 1024), large.bind(&storage),)
            .is_err()
    );
}

struct PinnedVerifier(Vec<u8>);

impl ClientCertVerifier for PinnedVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        identity.spki_der == self.0
    }
}

fn pump<G, V>(
    client: &mut State<clients::Pooled<'_>>,
    server: &mut State<servers::Pooled<'_, 0, G, V>>,
) -> usize
where
    G: shin::server::config::EarlyDataGuard,
    V: ClientCertVerifier,
{
    let mut received = 0;
    for _ in 0..16 {
        let client_wire = client.pending_send_slice();
        let client_len = client_wire.len();
        if client_len != 0 {
            api::reads::Server::read_tcp(server, client_wire, |plaintext| {
                received += plaintext.len();
            })
            .unwrap();
            client.consume_pending_send(client_len).unwrap();
        }

        let server_wire = server.pending_send_slice();
        let server_len = server_wire.len();
        if server_len != 0 {
            api::reads::Client::read_tcp(client, server_wire, |plaintext| {
                received += plaintext.len();
            })
            .unwrap();
            server.consume_pending_send(server_len).unwrap();
        }

        if client_len == 0 && server_len == 0 {
            break;
        }
    }
    received
}

#[test]
fn mutual_server_handshake_allocates_nothing_after_construction() {
    assert_eq!(
        std::mem::size_of::<servers::Pooled<'static, 0, NoGuard, ClientAuthVerifier<PinnedVerifier>>>(
        ),
        2 * std::mem::size_of::<usize>(),
    );

    let server_signing = SigningKey::from_seed(&[21; 32]).unwrap();
    let server_pubkey = *server_signing.pubkey().unwrap();
    let client_signing = SigningKey::from_seed(&[22; 32]).unwrap();
    let client_spki =
        shin::identity::spki::SubjectPublicKey::Ed25519(*client_signing.pubkey().unwrap())
            .encode()
            .unwrap();
    let shard = Shard::with_client_auth(
        Config {
            source: CertSource::RawPublicKey {
                signing_key: server_signing,
            },
            alpn_protocols: Vec::new(),
            ticket_keys: None,
        },
        ClientAuth::Required,
        PinnedVerifier(client_spki),
    )
    .unwrap();
    type ServerRole = roles::Server<roles::Mutual<NoGuard, PinnedVerifier>>;
    type ServerTls = tls::Tls<ServerRole>;
    type ClientTls = tls::Tls<roles::Client>;
    let server_storage = endpoints::SessionStorage::<ServerRole>::try_with_capacity(1).unwrap();
    let mut server_runtime = ServerTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        server_storage.bind_endpoint(shard),
    )
    .unwrap();
    let mut server = server_runtime.open_state().unwrap().unwrap();
    let client_plan = ClientPlan::mutual(
        client_config(server_pubkey),
        Identity::RawPublicKey {
            signing_key: client_signing,
        },
    )
    .unwrap();
    let client_storage = endpoints::SessionStorage::<roles::Client>::try_with_capacity(1).unwrap();
    let mut client_runtime = ClientTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        endpoints::Configuration::from_plan(client_plan).bind(&client_storage),
    )
    .unwrap();
    let mut client = client_runtime.open_state().unwrap().unwrap();

    let (_, allocations) = measured(|| pump(&mut client, &mut server));

    assert!(client.is_established());
    assert!(server.is_established());
    assert_eq!(allocations, 0);
}

#[test]
fn constructed_shin_state_handshake_and_records_allocate_nothing() {
    type ClientTls = tls::Tls<roles::Client>;
    type ServerTls = tls::Tls;

    let signing_key = SigningKey::from_seed(&[7; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let shard = Shard::new(Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap();
    let server_storage = endpoints::SessionStorage::<roles::Server>::try_with_capacity(1).unwrap();
    let mut server_runtime = ServerTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        server_storage.bind_endpoint(shard),
    )
    .unwrap();
    let mut server = server_runtime.open_state().unwrap().unwrap();
    let client_plan = ClientPlan::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    })
    .unwrap();
    let client_storage = endpoints::SessionStorage::<roles::Client>::try_with_capacity(1).unwrap();
    let mut client_runtime = ClientTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        endpoints::Configuration::from_plan(client_plan).bind(&client_storage),
    )
    .unwrap();
    let mut client = client_runtime.open_state().unwrap().unwrap();

    let (_, handshake_allocations) = measured(|| pump(&mut client, &mut server));

    assert!(client.is_established());
    assert!(server.is_established());
    assert_eq!(handshake_allocations, 0);

    let (received, record_allocations) = measured(|| {
        client
            .write_app(b"allocation-free application record")
            .unwrap();
        pump(&mut client, &mut server)
    });

    assert_eq!(received, b"allocation-free application record".len());
    assert_eq!(record_allocations, 0);
}

#[test]
fn complete_application_record_needs_no_receive_lease() {
    type ClientTls = tls::Tls<roles::Client>;
    type ServerTls = tls::Tls;

    let server_pubkey = *SigningKey::from_seed(&[11; 32]).unwrap().pubkey().unwrap();
    let server_storage = endpoints::SessionStorage::<roles::Server>::try_with_capacity(1).unwrap();
    let endpoint = endpoints::Configuration::server(Config {
        source: CertSource::RawPublicKey {
            signing_key: SigningKey::from_seed(&[11; 32]).unwrap(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap()
    .with_staged_record_budget(0)
    .with_ciphertext_budget(1);
    let mut server_runtime = ServerTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        endpoint.bind(&server_storage),
    )
    .unwrap();
    let mut server = server_runtime.open_state().unwrap().unwrap();
    let client_plan = ClientPlan::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    })
    .unwrap();
    let client_storage = endpoints::SessionStorage::<roles::Client>::try_with_capacity(1).unwrap();
    let mut client_runtime = ClientTls::runtime_context::<0>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        endpoints::Configuration::from_plan(client_plan).bind(&client_storage),
    )
    .unwrap();
    let mut client = client_runtime.open_state().unwrap().unwrap();

    for _ in 0..16 {
        let mut client_wire = client.pending_send_slice().to_vec();
        client.consume_pending_send(client_wire.len()).unwrap();
        if !client_wire.is_empty() {
            let read = api::reads::Server::read_tcp_in_place(&mut server, &mut client_wire);
            assert_ne!(read.status(), Read::Failed);
        }

        let server_wire = server.pending_send_slice().to_vec();
        server.consume_pending_send(server_wire.len()).unwrap();
        if !server_wire.is_empty() {
            api::reads::Client::read_tcp(&mut client, &server_wire, |_| {}).unwrap();
        }

        if client.is_established()
            && server.is_established()
            && client.pending_send_slice().is_empty()
            && server.pending_send_slice().is_empty()
        {
            break;
        }
    }
    assert!(client.is_established());
    assert!(server.is_established());
    assert_eq!(server_runtime.buffer_usage().recv_available(), 1);

    client.write_app(b"direct without scratch").unwrap();
    let mut wire = client.pending_send_slice().to_vec();
    client.consume_pending_send(wire.len()).unwrap();
    let read = api::reads::Server::read_tcp_in_place(&mut server, &mut wire);
    assert_ne!(read.status(), Read::Failed);
    assert_eq!(
        read.into_plain().flatten().copied().collect::<Vec<_>>(),
        b"direct without scratch"
    );
    assert_eq!(server_runtime.buffer_usage().recv_available(), 1);
}
