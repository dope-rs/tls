mod common;

use std::cell::Cell;
use std::rc::Rc;

use dope_net::wire::send::{SendStorage, Storage};
use dope_net::wire::{OpenReservation, RuntimeLimits, Wire};
use dope_tls::ClientCertSource;
use dope_tls::tls::{Client, ClientDial, ClientSetup, ClientSource, Endpoint, Tls};

type ClientTls = Tls<Client>;
type ServerTls = Tls;

#[test]
fn reserved_open_adds_only_the_runtime_reference() {
    type Committed = (
        <ClientTls as Wire>::Connection<'static>,
        <ClientTls as Wire>::SendStorage,
    );
    type Expected<'a> = (
        Committed,
        &'a mut <ClientTls as Wire>::RuntimeContext<'static>,
    );

    assert_eq!(
        size_of::<<ClientTls as Wire>::Open<'_, 'static>>(),
        size_of::<Expected<'_>>()
    );
    assert_eq!(
        align_of::<<ClientTls as Wire>::Open<'_, 'static>>(),
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
        resumption: None,
        enable_early_data: false,
    }
}

fn server_endpoint() -> Endpoint {
    Endpoint::server(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey {
            signing_key: common::signing_key(),
        },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .unwrap()
}

struct CountingSource {
    setup: ClientSetup,
    calls: Rc<Cell<usize>>,
}

impl ClientSource for CountingSource {
    fn next(&mut self) -> ClientDial {
        self.calls.set(self.calls.get() + 1);
        self.setup.for_next_dial()
    }
}

#[test]
fn cancelled_open_preserves_client_setup() {
    let storage = ClientTls::connection_storage(1).unwrap();
    let endpoint: Endpoint<Client> = Endpoint::client(client_config()).unwrap();
    let mut runtime =
        ClientTls::runtime_context(RuntimeLimits::new(1, 0, 64 * 1024), endpoint.bind(&storage))
            .unwrap();

    drop(ClientTls::prepare_open(&mut runtime).unwrap().unwrap());

    let connection = ClientTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert!(ClientTls::prepare_open(&mut runtime).unwrap().is_none());
    drop(connection);
    assert!(ClientTls::prepare_open(&mut runtime).unwrap().is_some());
}

#[test]
fn standard_client_setup_fills_multiple_slots_and_reopens_them() {
    const CAPACITY: usize = 8;
    let limits = RuntimeLimits::new(CAPACITY, 0, 64 * 1024);
    let storage = ClientTls::connection_storage(CAPACITY).unwrap();
    let endpoint: Endpoint<Client> = Endpoint::client(client_config()).unwrap();
    let mut runtime = ClientTls::runtime_context(limits, endpoint.bind(&storage)).unwrap();

    let mut connections = (0..CAPACITY)
        .map(|_| {
            ClientTls::prepare_open(&mut runtime)
                .unwrap()
                .unwrap()
                .commit()
        })
        .collect::<Vec<_>>();
    assert!(ClientTls::prepare_open(&mut runtime).unwrap().is_none());

    drop(connections.pop());
    let replacement = ClientTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();

    drop((connections, replacement));
}

#[test]
fn resource_backpressure_never_advances_the_client_source() {
    type CountingTls = Tls<Client<CountingSource>>;

    let calls = Rc::new(Cell::new(0));
    let storage = CountingTls::connection_storage(1).unwrap();
    let endpoint = Endpoint::client_source(CountingSource {
        setup: ClientSetup::new(client_config()).unwrap(),
        calls: calls.clone(),
    });
    let mut runtime =
        CountingTls::runtime_context(RuntimeLimits::new(1, 0, 64 * 1024), endpoint.bind(&storage))
            .unwrap();

    let connection = CountingTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert_eq!(calls.get(), 1);
    assert!(CountingTls::prepare_open(&mut runtime).unwrap().is_none());
    assert_eq!(calls.get(), 1);

    drop(connection);
    assert!(CountingTls::prepare_open(&mut runtime).unwrap().is_some());
    assert_eq!(calls.get(), 2);
}

#[test]
fn mutual_client_setup_fills_multiple_slots_and_reopens_them() {
    const CAPACITY: usize = 8;
    let limits = RuntimeLimits::new(CAPACITY, 0, 64 * 1024);
    let storage = ClientTls::connection_storage(CAPACITY).unwrap();
    let endpoint: Endpoint<Client> = Endpoint::client_mutual(
        client_config(),
        ClientCertSource::RawPublicKey {
            signing_key: common::signing_key(),
        },
    )
    .unwrap();
    let mut runtime = ClientTls::runtime_context(limits, endpoint.bind(&storage)).unwrap();

    let mut connections = (0..CAPACITY)
        .map(|_| {
            ClientTls::prepare_open(&mut runtime)
                .unwrap()
                .unwrap()
                .commit()
        })
        .collect::<Vec<_>>();
    assert!(ClientTls::prepare_open(&mut runtime).unwrap().is_none());

    drop(connections.pop());
    let replacement = ClientTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();

    drop((connections, replacement));
}

#[test]
fn dropped_connection_recycles_the_runtime_side_slot() {
    let storage = ServerTls::connection_storage(1).unwrap();
    let mut runtime = ServerTls::runtime_context(
        RuntimeLimits::new(1, 0, 64 * 1024),
        server_endpoint().bind(&storage),
    )
    .unwrap();

    let connection = ServerTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert!(ServerTls::prepare_open(&mut runtime).unwrap().is_none());
    drop(connection);

    let _reused = ServerTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
}

#[test]
fn committed_connection_borrows_side_storage_but_not_runtime() {
    let storage = ServerTls::connection_storage(1).unwrap();
    let connection = {
        let mut runtime = ServerTls::runtime_context(
            RuntimeLimits::new(1, 0, 64 * 1024),
            server_endpoint().bind(&storage),
        )
        .unwrap();
        ServerTls::prepare_open(&mut runtime)
            .unwrap()
            .unwrap()
            .commit()
    };

    drop(connection);
}

#[test]
fn opening_connections_does_not_eagerly_lease_send_or_receive_buffers() {
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);
    let server_storage = ServerTls::connection_storage(1).unwrap();
    let mut server_runtime =
        ServerTls::runtime_context(limits, server_endpoint().bind(&server_storage)).unwrap();
    let server_initial = server_runtime.buffer_usage();
    assert_eq!(server_initial.recv_available(), 1);
    assert_eq!(server_initial.pending_available(), 1);
    assert_eq!(server_initial.send_available(), 1);

    let server = ServerTls::prepare_open(&mut server_runtime)
        .unwrap()
        .unwrap()
        .commit();
    let server_open = server_runtime.buffer_usage();
    assert_eq!(server_open.recv_available(), 1);
    assert_eq!(server_open.pending_available(), 1);
    assert_eq!(server_open.send_available(), 1);
    drop(server);

    let endpoint: Endpoint<Client> = Endpoint::client(client_config()).unwrap();
    let client_storage = ClientTls::connection_storage(1).unwrap();
    let mut client_runtime =
        ClientTls::runtime_context(limits, endpoint.bind(&client_storage)).unwrap();
    let client = ClientTls::prepare_open(&mut client_runtime)
        .unwrap()
        .unwrap()
        .commit();
    let client_open = client_runtime.buffer_usage();
    assert_eq!(client_open.recv_available(), 1);
    assert_eq!(client_open.pending_available(), 0);
    assert_eq!(client_open.send_available(), 1);

    drop(client);
    let client_dropped = client_runtime.buffer_usage();
    assert_eq!(client_dropped.recv_available(), 1);
    assert_eq!(client_dropped.pending_available(), 1);
    assert_eq!(client_dropped.send_available(), 1);
}

#[test]
fn send_buffer_is_leased_exactly_until_ciphertext_completion() {
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);
    let endpoint: Endpoint<Client> = Endpoint::client(client_config()).unwrap();
    let storage = ClientTls::connection_storage(1).unwrap();
    let mut runtime = ClientTls::runtime_context(limits, endpoint.bind(&storage)).unwrap();
    let (mut wire, mut send) = ClientTls::prepare_open(&mut runtime)
        .unwrap()
        .unwrap()
        .commit();
    assert_eq!(runtime.buffer_usage().send_available(), 1);

    drop(ClientTls::flush_pending(
        &mut wire,
        Storage::new(&mut send, 0),
    ));
    let written = send.as_slice().len();
    assert_ne!(written, 0);
    assert_eq!(runtime.buffer_usage().pending_available(), 1);
    assert_eq!(runtime.buffer_usage().send_available(), 0);

    drop(ClientTls::after_send(
        &mut wire,
        Storage::new(&mut send, 0),
        dope_net::wire::send::Sent::try_from_submission(written, written).unwrap(),
    ));
    assert!(send.as_slice().is_empty());
    assert_eq!(runtime.buffer_usage().send_available(), 1);
}
