use dope::net::wire::receive::Strategy;
use dope::net::wire::send::{Availability, Storage, StorageBackend};
use dope::net::wire::{OpenReservation, OpenRollback, RuntimeLimits, Wire};
use dope_tls::Identity;
use dope_tls::tls::{self, endpoints, roles};

type ClientTls = tls::Tls<roles::Client>;
type ServerTls = tls::Tls;
const ROUTE_ID: u8 = 0;

#[test]
fn reserved_open_adds_only_the_runtime_reference() {
    type Committed = (
        <ClientTls as Wire>::Connection<'static, ROUTE_ID>,
        <ClientTls as Wire>::StorageBackend<'static>,
    );
    type Expected<'a> = (
        Committed,
        &'a mut <ClientTls as Wire>::RuntimeContext<'static, ROUTE_ID>,
    );

    assert_eq!(
        size_of::<<ClientTls as Wire>::Open<'_, 'static, ROUTE_ID>>(),
        size_of::<Expected<'_>>()
    );
    assert_eq!(
        align_of::<<ClientTls as Wire>::Open<'_, 'static, ROUTE_ID>>(),
        align_of::<Expected<'_>>()
    );
}

fn client_config() -> shin::client::config::Config {
    shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: [9; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    }
}

fn server_endpoint() -> endpoints::Configuration {
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
fn cancelled_open_preserves_client_setup() {
    let storage = ClientTls::connection_storage::<ROUTE_ID>(1).unwrap();
    let endpoint = endpoints::Configuration::client(client_config()).unwrap();
    let mut runtime = ClientTls::runtime_context::<ROUTE_ID>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        endpoint.bind(&storage),
    )
    .unwrap();

    drop(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .unwrap(),
    );

    let connection = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert!(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_none()
    );
    drop(connection);
    assert!(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_some()
    );
}

#[test]
fn rollback_replacement_releases_the_displaced_open() {
    const CAPACITY: usize = 2;
    let storage = ClientTls::connection_storage::<ROUTE_ID>(CAPACITY).unwrap();
    let endpoint = endpoints::Configuration::client(client_config()).unwrap();
    let mut runtime = ClientTls::runtime_context::<ROUTE_ID>(
        RuntimeLimits::new(CAPACITY, 0, 64 * 1024),
        endpoint.bind(&storage),
    )
    .unwrap();

    let first = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    let second = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert_eq!(runtime.buffer_usage().send_available(), 0);

    OpenRollback::rollback_open(&mut runtime, first);
    OpenRollback::rollback_open(&mut runtime, second);
    assert_eq!(runtime.buffer_usage().send_available(), 1);

    let retained = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    let replacement = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert_eq!(runtime.buffer_usage().send_available(), 0);
    assert!(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_none()
    );

    drop((retained, replacement));
    assert_eq!(runtime.buffer_usage().send_available(), CAPACITY);
}

#[test]
fn standard_client_setup_fills_multiple_slots_and_reopens_them() {
    const CAPACITY: usize = 8;
    let limits = RuntimeLimits::new(CAPACITY, 0, 64 * 1024);
    let storage = ClientTls::connection_storage::<ROUTE_ID>(CAPACITY).unwrap();
    let endpoint = endpoints::Configuration::client(client_config()).unwrap();
    let mut runtime =
        ClientTls::runtime_context::<ROUTE_ID>(limits, endpoint.bind(&storage)).unwrap();

    let mut connections = (0..CAPACITY)
        .map(|_| {
            ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
                .unwrap()
                .unwrap()
                .commit()
        })
        .collect::<Vec<_>>();
    assert!(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_none()
    );

    drop(connections.pop());
    let replacement = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();

    drop((connections, replacement));
}

#[test]
fn standard_server_setup_fills_multiple_slots_and_reopens_them() {
    const CAPACITY: usize = 8;
    let limits = RuntimeLimits::new(CAPACITY, 0, 64 * 1024);
    let storage = ServerTls::connection_storage::<ROUTE_ID>(CAPACITY).unwrap();
    let mut runtime =
        ServerTls::runtime_context::<ROUTE_ID>(limits, server_endpoint().bind(&storage)).unwrap();

    let mut connections = (0..CAPACITY)
        .map(|_| {
            ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
                .unwrap()
                .unwrap()
                .commit()
        })
        .collect::<Vec<_>>();
    assert!(
        ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_none()
    );

    drop(connections.pop());
    let replacement = ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();

    drop((connections, replacement));
}

#[test]
fn ciphertext_backpressure_stops_before_client_construction() {
    const CAPACITY: usize = 2;
    let limits = RuntimeLimits::new(CAPACITY, 0, 64 * 1024);
    let storage = ClientTls::connection_storage::<ROUTE_ID>(CAPACITY).unwrap();
    let endpoint = endpoints::Configuration::client(client_config())
        .unwrap()
        .with_ciphertext_budget(1);
    let mut runtime =
        ClientTls::runtime_context::<ROUTE_ID>(limits, endpoint.bind(&storage)).unwrap();

    let first = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert_eq!(runtime.buffer_usage().send_available(), 0);
    assert!(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_none()
    );

    drop(first);
    assert!(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_some()
    );
}

#[test]
fn mutual_client_setup_fills_multiple_slots_and_reopens_them() {
    const CAPACITY: usize = 8;
    let limits = RuntimeLimits::new(CAPACITY, 0, 64 * 1024);
    let storage = ClientTls::connection_storage::<ROUTE_ID>(CAPACITY).unwrap();
    let endpoint = endpoints::Configuration::client_mutual(
        client_config(),
        Identity::RawPublicKey {
            signing_key: super::common::signing_key(),
        },
    )
    .unwrap();
    let mut runtime =
        ClientTls::runtime_context::<ROUTE_ID>(limits, endpoint.bind(&storage)).unwrap();

    let mut connections = (0..CAPACITY)
        .map(|_| {
            ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
                .unwrap()
                .unwrap()
                .commit()
        })
        .collect::<Vec<_>>();
    assert!(
        ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_none()
    );

    drop(connections.pop());
    let replacement = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();

    drop((connections, replacement));
}

#[test]
fn dropped_connection_recycles_the_runtime_side_slot() {
    let storage = ServerTls::connection_storage::<ROUTE_ID>(1).unwrap();
    let mut runtime = ServerTls::runtime_context::<ROUTE_ID>(
        RuntimeLimits::new(1, 0, 64 * 1024),
        server_endpoint().bind(&storage),
    )
    .unwrap();

    let connection = ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert!(
        ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .is_none()
    );
    drop(connection);

    let _reused = ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
}

#[test]
fn committed_connection_borrows_side_storage_but_not_runtime() {
    let storage = ServerTls::connection_storage::<ROUTE_ID>(1).unwrap();
    let connection = {
        let mut runtime = ServerTls::runtime_context::<ROUTE_ID>(
            RuntimeLimits::new(1, 0, 64 * 1024),
            server_endpoint().bind(&storage),
        )
        .unwrap();
        ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
            .unwrap()
            .unwrap()
            .commit()
    };

    drop(connection);
}

#[test]
fn opening_connections_leases_only_client_hello_ciphertext() {
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);
    let server_storage = ServerTls::connection_storage::<ROUTE_ID>(1).unwrap();
    let mut server_runtime =
        ServerTls::runtime_context::<ROUTE_ID>(limits, server_endpoint().bind(&server_storage))
            .unwrap();
    let server_initial = server_runtime.buffer_usage();
    assert_eq!(server_initial.recv_available(), 2);
    assert_eq!(server_initial.send_available(), 1);

    let server = ServerTls::prepare_open::<ROUTE_ID>(&mut server_runtime)
        .unwrap()
        .unwrap()
        .commit();
    let server_open = server_runtime.buffer_usage();
    assert_eq!(server_open.recv_available(), 2);
    assert_eq!(server_open.send_available(), 1);
    let (server_wire, server_send) = server;
    assert_eq!(
        StorageBackend::release(server_send),
        Availability::Unchanged
    );
    drop(server_wire);

    let endpoint = endpoints::Configuration::client(client_config()).unwrap();
    let client_storage = ClientTls::connection_storage::<ROUTE_ID>(1).unwrap();
    let mut client_runtime =
        ClientTls::runtime_context::<ROUTE_ID>(limits, endpoint.bind(&client_storage)).unwrap();
    let client = ClientTls::prepare_open::<ROUTE_ID>(&mut client_runtime)
        .unwrap()
        .unwrap()
        .commit();
    let client_open = client_runtime.buffer_usage();
    assert_eq!(client_open.recv_available(), 2);
    assert_eq!(client_open.send_available(), 0);

    let (client_wire, client_send) = client;
    assert_eq!(StorageBackend::release(client_send), Availability::Released);
    drop(client_wire);
    let client_dropped = client_runtime.buffer_usage();
    assert_eq!(client_dropped.recv_available(), 2);
    assert_eq!(client_dropped.send_available(), 1);
}

#[test]
fn send_buffer_is_leased_exactly_until_ciphertext_completion() {
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);
    let endpoint = endpoints::Configuration::client(client_config()).unwrap();
    let storage = ClientTls::connection_storage::<ROUTE_ID>(1).unwrap();
    let mut runtime =
        ClientTls::runtime_context::<ROUTE_ID>(limits, endpoint.bind(&storage)).unwrap();
    let (mut wire, mut send) = ClientTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert_eq!(runtime.buffer_usage().send_available(), 0);

    drop(ClientTls::flush_pending(
        &mut wire,
        Storage::from_raw(&mut send, 0),
    ));
    let written = send.as_slice().len();
    assert_ne!(written, 0);
    assert_eq!(runtime.buffer_usage().send_available(), 0);

    let completed = ClientTls::after_send(
        &mut wire,
        Storage::from_raw(&mut send, 0),
        dope::net::wire::send::Sent::try_from_submission(written, written).unwrap(),
    );
    assert_eq!(
        completed.availability(),
        dope::net::wire::send::Availability::Released
    );
    drop(completed);
    assert!(send.as_slice().is_empty());
    assert_eq!(runtime.buffer_usage().send_available(), 1);
}

#[test]
fn receive_transaction_returns_empty_resources_on_drop() {
    const CONNECTIONS: usize = 3;
    let limits = RuntimeLimits::new(CONNECTIONS, 0, 64 * 1024);
    let storage = ServerTls::connection_storage::<ROUTE_ID>(CONNECTIONS).unwrap();
    let endpoint = server_endpoint()
        .with_staged_record_budget(CONNECTIONS - 1)
        .with_ciphertext_budget(2);
    let mut runtime =
        ServerTls::runtime_context::<ROUTE_ID>(limits, endpoint.bind(&storage)).unwrap();
    let (mut first, mut first_send) = ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    let (mut second, mut second_send) = ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    let (mut third, mut third_send) = ServerTls::prepare_open::<ROUTE_ID>(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();

    let recv_available = runtime.buffer_usage().recv_available();
    let send_available = runtime.buffer_usage().send_available();
    for (wire, send) in [
        (&mut first, &mut first_send),
        (&mut second, &mut second_send),
        (&mut third, &mut third_send),
    ] {
        let Ok(receive) = <<ServerTls as Wire>::Receive as Strategy<ServerTls>>::reserve::<ROUTE_ID>(
            wire,
            send,
            &mut runtime,
        ) else {
            panic!("receive resources");
        };
        drop(receive);
        assert_eq!(runtime.buffer_usage().recv_available(), recv_available);
        assert_eq!(runtime.buffer_usage().send_available(), send_available);
    }
}
