use dope::net::wire::receive::{Strategy, Transaction};
use dope::net::wire::send::{Sent, Storage, StorageBackend};
use dope::net::wire::{self, OpenReservation, RecvChunk, RuntimeLimits, Wire};
use dope_tls::tls::{self, endpoints, roles};

mod sealed;

type ClientTls = tls::Tls<roles::Client>;
type ServerTls = tls::Tls;
const ROUTE_ID: u8 = 7;

fn drain_pending<'d, R: roles::Protocol>(
    wire: &mut tls::Connection<'d, R, ROUTE_ID>,
    send: &mut tls::SendState<'d>,
) -> Vec<u8> {
    drop(tls::Tls::<R>::flush_pending(
        wire,
        Storage::from_raw(send, 0),
    ));
    let output = send.as_slice().to_vec();
    if !output.is_empty() {
        complete_send(wire, send, output.len());
    }
    output
}

fn complete_send<'d, R: roles::Protocol>(
    wire: &mut tls::Connection<'d, R, ROUTE_ID>,
    send: &mut tls::SendState<'d>,
    len: usize,
) {
    let sent = Sent::try_from_submission(len, len).expect("valid send");
    drop(tls::Tls::<R>::after_send(
        wire,
        Storage::from_raw(send, 0),
        sent,
    ));
}

fn send_static<'d, R: roles::Protocol>(
    wire: &mut tls::Connection<'d, R, ROUTE_ID>,
    send: &mut tls::SendState<'d>,
    bytes: &'static [u8],
) -> Vec<u8> {
    let plain = sealed::static_plain(bytes);
    drop(tls::Tls::<R>::prepare_send(
        wire,
        Storage::from_raw(send, bytes.len()),
        plain,
    ));
    drain_pending(wire, send)
}

fn client_endpoint(server_pubkey: [u8; 32]) -> endpoints::Configuration<roles::Client> {
    endpoints::Configuration::client(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        enable_early_data: false,
    })
    .expect("valid client endpoint")
}

fn server_endpoint(
    signing_key: shin::crypto::sig::SigningKey,
) -> endpoints::Configuration<roles::Server> {
    endpoints::Configuration::server(shin::server::config::Config {
        source: shin::server::config::CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    })
    .expect("valid server endpoint")
}

fn process_empty<'d, R: roles::Protocol>(
    wire: &mut tls::Connection<'d, R, ROUTE_ID>,
    runtime: &mut <tls::Tls<R> as Wire>::RuntimeContext<'d, ROUTE_ID>,
    send: &mut tls::SendState<'d>,
    bytes: &mut [u8],
) {
    let Ok(mut receive) = <<tls::Tls<R> as Wire>::Receive as Strategy<tls::Tls<R>>>::reserve::<
        ROUTE_ID,
    >(wire, send, runtime) else {
        panic!("receive resources");
    };
    let capacity = wire::batch::Capacity::<tls::Tls<R>>::full();
    let batch = Transaction::process(&mut receive, bytes, &capacity);
    assert_eq!(batch.len(), 0, "receive must not yield application data");
    drop(batch);
}

fn process_one_owned<'d, R: roles::Protocol>(
    wire: &mut tls::Connection<'d, R, ROUTE_ID>,
    runtime: &mut <tls::Tls<R> as Wire>::RuntimeContext<'d, ROUTE_ID>,
    send: &mut tls::SendState<'d>,
    bytes: &mut [u8],
) -> o3::buffer::bytes::Bytes<o3::buffer::bytes::Retained> {
    let Ok(mut receive) = <<tls::Tls<R> as Wire>::Receive as Strategy<tls::Tls<R>>>::reserve::<
        ROUTE_ID,
    >(wire, send, runtime) else {
        panic!("receive resources");
    };
    let capacity = wire::batch::Capacity::<tls::Tls<R>>::full();
    let mut batch = Transaction::process(&mut receive, bytes, &capacity);
    assert_eq!(batch.len(), 1);
    match batch.next().expect("one application chunk") {
        RecvChunk::Owned(chunk) => o3::buffer::bytes::Retainable::into_retained(chunk),
        RecvChunk::Borrowed(_) => panic!("fragmented record must own a scratch lease"),
    }
}

fn process_batch<'d, R: roles::Protocol>(
    wire: &mut tls::Connection<'d, R, ROUTE_ID>,
    runtime: &mut <tls::Tls<R> as Wire>::RuntimeContext<'d, ROUTE_ID>,
    send: &mut tls::SendState<'d>,
    bytes: &mut [u8],
) -> (usize, Vec<u8>) {
    process_batch_with_capacity(wire, runtime, send, bytes, usize::MAX)
}

fn process_batch_with_capacity<'d, R: roles::Protocol>(
    wire: &mut tls::Connection<'d, R, ROUTE_ID>,
    runtime: &mut <tls::Tls<R> as Wire>::RuntimeContext<'d, ROUTE_ID>,
    send: &mut tls::SendState<'d>,
    bytes: &mut [u8],
    available: usize,
) -> (usize, Vec<u8>) {
    let Ok(mut receive) = <<tls::Tls<R> as Wire>::Receive as Strategy<tls::Tls<R>>>::reserve::<
        ROUTE_ID,
    >(wire, send, runtime) else {
        panic!("receive resources");
    };
    let capacity =
        wire::batch::Capacity::<tls::Tls<R>>::fit(available).expect("supported receive capacity");
    let batch = Transaction::process(&mut receive, bytes, &capacity);
    let chunks = batch.len();
    let mut plain = Vec::new();
    for chunk in batch {
        match chunk {
            RecvChunk::Borrowed(chunk) => plain.extend_from_slice(chunk.as_slice()),
            RecvChunk::Owned(chunk) => plain.extend_from_slice(chunk.as_slice()),
        }
    }
    (chunks, plain)
}

fn pump_handshake<'client, 'server>(
    client: &mut tls::Connection<'client, roles::Client, ROUTE_ID>,
    client_runtime: &mut <ClientTls as Wire>::RuntimeContext<'client, ROUTE_ID>,
    client_send: &mut tls::SendState<'client>,
    server: &mut tls::Connection<'server, roles::Server, ROUTE_ID>,
    server_runtime: &mut <ServerTls as Wire>::RuntimeContext<'server, ROUTE_ID>,
    server_send: &mut tls::SendState<'server>,
) {
    for _ in 0..16 {
        let mut from_client = drain_pending(client, client_send);
        let mut progressed = !from_client.is_empty();
        if !from_client.is_empty() {
            process_empty(server, server_runtime, server_send, &mut from_client);
        }

        let mut from_server = drain_pending(server, server_send);
        progressed |= !from_server.is_empty();
        if !from_server.is_empty() {
            process_empty(client, client_runtime, client_send, &mut from_server);
        }

        if !progressed {
            return;
        }
    }
    panic!("TLS handshake did not quiesce");
}

fn pump_client_state_handshake<'client>(
    client: &mut tls::Connection<'client, roles::Client, ROUTE_ID>,
    client_runtime: &mut <ClientTls as Wire>::RuntimeContext<'client, ROUTE_ID>,
    client_send: &mut tls::SendState<'client>,
    server: &mut super::common::TestServer,
) {
    for _ in 0..16 {
        let from_client = drain_pending(client, client_send);
        let mut progressed = !from_client.is_empty();
        if !from_client.is_empty() {
            server
                .read_tcp(&from_client)
                .expect("server handshake read");
        }

        let mut from_server = server.pull_send();
        progressed |= !from_server.is_empty();
        if !from_server.is_empty() {
            process_empty(client, client_runtime, client_send, &mut from_server);
        }
        if !progressed {
            return;
        }
    }
    panic!("TLS handshake did not quiesce");
}

#[test]
fn direct_records_over_batch_limit_compact_only_the_overflow_tail() {
    const RECORDS: usize = 33;

    let signing_key = super::common::signing_key();
    let server_pubkey = *signing_key.pubkey().expect("server public key");
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);
    let client_storage = endpoints::SessionStorage::<roles::Client, ROUTE_ID>::try_with_capacity(1)
        .expect("client storage");
    let server_storage = endpoints::SessionStorage::<roles::Server, ROUTE_ID>::try_with_capacity(1)
        .expect("server storage");
    let mut client_runtime = ClientTls::runtime_context::<ROUTE_ID>(
        limits,
        client_endpoint(server_pubkey).bind(&client_storage),
    )
    .expect("client runtime");
    let mut server_runtime = ServerTls::runtime_context::<ROUTE_ID>(
        limits,
        server_endpoint(signing_key).bind(&server_storage),
    )
    .expect("server runtime");
    let (mut client, mut client_send) = ClientTls::prepare_open::<ROUTE_ID>(&mut client_runtime)
        .expect("client open")
        .expect("client resources")
        .commit();
    let (mut server, mut server_send) = ServerTls::prepare_open::<ROUTE_ID>(&mut server_runtime)
        .expect("server open")
        .expect("server resources")
        .commit();
    pump_handshake(
        &mut client,
        &mut client_runtime,
        &mut client_send,
        &mut server,
        &mut server_runtime,
        &mut server_send,
    );

    let mut ciphertext = Vec::new();
    for _ in 0..RECORDS {
        ciphertext.extend_from_slice(&send_static(&mut client, &mut client_send, b"x"));
    }
    let (chunks, plain) = process_batch(
        &mut server,
        &mut server_runtime,
        &mut server_send,
        &mut ciphertext,
    );

    use dope::net::wire::batch::raw::Source;

    assert_eq!(
        chunks,
        <<ServerTls as Wire>::RecvBatch<'static> as Source>::MAX_ITEMS.get()
    );
    assert_eq!(plain, vec![b'x'; RECORDS]);
}

#[test]
fn tls_batch_capacity_is_one_word_and_clamped_to_its_source_contract() {
    assert_eq!(
        std::mem::size_of::<wire::batch::Capacity<ServerTls>>(),
        std::mem::size_of::<usize>()
    );
    assert!(wire::batch::Capacity::<ServerTls>::fit(1).is_none());
    assert_eq!(
        wire::batch::Capacity::<ServerTls>::fit(2)
            .expect("minimum capacity")
            .items()
            .get(),
        2
    );
    assert_eq!(
        wire::batch::Capacity::<ServerTls>::fit(usize::MAX)
            .expect("full capacity")
            .items()
            .get(),
        32
    );
}

#[test]
fn staged_and_direct_records_compact_to_minimum_dynamic_capacity() {
    const DIRECT_RECORDS: usize = 32;

    let signing_key = super::common::signing_key();
    let server_pubkey = *signing_key.pubkey().expect("server public key");
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);
    let client_storage = endpoints::SessionStorage::<roles::Client, ROUTE_ID>::try_with_capacity(1)
        .expect("client storage");
    let server_storage = endpoints::SessionStorage::<roles::Server, ROUTE_ID>::try_with_capacity(1)
        .expect("server storage");
    let mut client_runtime = ClientTls::runtime_context::<ROUTE_ID>(
        limits,
        client_endpoint(server_pubkey).bind(&client_storage),
    )
    .expect("client runtime");
    let mut server_runtime = ServerTls::runtime_context::<ROUTE_ID>(
        limits,
        server_endpoint(signing_key).bind(&server_storage),
    )
    .expect("server runtime");
    let (mut client, mut client_send) = ClientTls::prepare_open::<ROUTE_ID>(&mut client_runtime)
        .expect("client open")
        .expect("client resources")
        .commit();
    let (mut server, mut server_send) = ServerTls::prepare_open::<ROUTE_ID>(&mut server_runtime)
        .expect("server open")
        .expect("server resources")
        .commit();
    pump_handshake(
        &mut client,
        &mut client_runtime,
        &mut client_send,
        &mut server,
        &mut server_runtime,
        &mut server_send,
    );

    let first = send_static(&mut client, &mut client_send, b"s");
    let mut prefix = first[..1].to_vec();
    process_empty(
        &mut server,
        &mut server_runtime,
        &mut server_send,
        &mut prefix,
    );
    let mut ciphertext = first[1..].to_vec();
    for _ in 0..DIRECT_RECORDS {
        ciphertext.extend_from_slice(&send_static(&mut client, &mut client_send, b"d"));
    }
    let (chunks, plain) = process_batch_with_capacity(
        &mut server,
        &mut server_runtime,
        &mut server_send,
        &mut ciphertext,
        2,
    );

    assert_eq!(chunks, 2);
    assert_eq!(plain[0], b's');
    assert_eq!(&plain[1..], vec![b'd'; DIRECT_RECORDS]);
}

#[test]
fn wire_process_recv_retains_a_then_stages_and_delivers_b() {
    const A: &[u8] = b"record A";
    const B: &[u8] = b"record B";

    let signing_key = super::common::signing_key();
    let server_pubkey = *signing_key.pubkey().expect("server public key");
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);

    let client_storage = endpoints::SessionStorage::<roles::Client, ROUTE_ID>::try_with_capacity(1)
        .expect("client storage");
    let server_storage = endpoints::SessionStorage::<roles::Server, ROUTE_ID>::try_with_capacity(1)
        .expect("server storage");
    let mut client_runtime = ClientTls::runtime_context::<ROUTE_ID>(
        limits,
        client_endpoint(server_pubkey).bind(&client_storage),
    )
    .expect("client runtime");
    let mut server_runtime = ServerTls::runtime_context::<ROUTE_ID>(
        limits,
        server_endpoint(signing_key).bind(&server_storage),
    )
    .expect("server runtime");
    let (mut client, mut client_send) = ClientTls::prepare_open::<ROUTE_ID>(&mut client_runtime)
        .expect("client open")
        .expect("client resources")
        .commit();
    let (mut server, mut server_send) = ServerTls::prepare_open::<ROUTE_ID>(&mut server_runtime)
        .expect("server open")
        .expect("server resources")
        .commit();

    pump_handshake(
        &mut client,
        &mut client_runtime,
        &mut client_send,
        &mut server,
        &mut server_runtime,
        &mut server_send,
    );

    let a = send_static(&mut client, &mut client_send, A);
    let b = send_static(&mut client, &mut client_send, B);
    assert!(
        !a.is_empty() && !b.is_empty(),
        "handshake must establish sending"
    );

    let mut recv_1 = a[..1].to_vec();
    process_empty(
        &mut server,
        &mut server_runtime,
        &mut server_send,
        &mut recv_1,
    );
    assert_eq!(server_runtime.buffer_usage().recv_available(), 1);

    let mut recv_2 = a[1..].to_vec();
    recv_2.extend_from_slice(&b[..1]);
    let a_chunk = process_one_owned(
        &mut server,
        &mut server_runtime,
        &mut server_send,
        &mut recv_2,
    );
    assert_eq!(a_chunk.as_slice(), A);
    assert_eq!(
        server_runtime.buffer_usage().recv_available(),
        0,
        "A is retained while B owns the next partial scratch"
    );
    drop(a_chunk);
    assert_eq!(server_runtime.buffer_usage().recv_available(), 1);

    let mut recv_3 = b[1..].to_vec();
    let b_chunk = process_one_owned(
        &mut server,
        &mut server_runtime,
        &mut server_send,
        &mut recv_3,
    );
    assert_eq!(b_chunk.as_slice(), B);
    drop(b_chunk);
    assert_eq!(server_runtime.buffer_usage().recv_available(), 2);
}

#[test]
fn established_receive_ignores_inflight_and_exhausted_ciphertext_slot() {
    const INBOUND: &[u8] = b"inbound while outbound is in flight";
    const OUTBOUND: &[u8] = b"outbound held by the kernel";
    const SECOND_OUTBOUND: &[u8] = b"outbound before key update response";

    let signing_key = super::common::signing_key();
    let server_pubkey = *signing_key.pubkey().expect("server public key");
    let limits = RuntimeLimits::new(1, 0, 64 * 1024);
    let client_storage = endpoints::SessionStorage::<roles::Client, ROUTE_ID>::try_with_capacity(1)
        .expect("client storage");
    let mut client_runtime = ClientTls::runtime_context::<ROUTE_ID>(
        limits,
        client_endpoint(server_pubkey)
            .with_ciphertext_budget(1)
            .bind(&client_storage),
    )
    .expect("client runtime");
    let (mut client, mut client_send) = ClientTls::prepare_open::<ROUTE_ID>(&mut client_runtime)
        .expect("client open")
        .expect("client resources")
        .commit();
    let mut server = super::common::raw_server(signing_key);

    pump_client_state_handshake(
        &mut client,
        &mut client_runtime,
        &mut client_send,
        &mut server,
    );

    server.write_app(INBOUND).expect("server application write");
    let mut inbound = server.pull_send();
    let plain = sealed::static_plain(OUTBOUND);
    drop(ClientTls::prepare_send(
        &mut client,
        Storage::from_raw(&mut client_send, OUTBOUND.len()),
        plain,
    ));
    let outbound = client_send.as_slice().to_vec();
    assert!(!outbound.is_empty());
    assert_eq!(client_runtime.buffer_usage().send_available(), 0);

    let mut first_byte = inbound.drain(..1).collect::<Vec<_>>();
    process_empty(
        &mut client,
        &mut client_runtime,
        &mut client_send,
        &mut first_byte,
    );
    let received = process_one_owned(
        &mut client,
        &mut client_runtime,
        &mut client_send,
        &mut inbound,
    );
    assert_eq!(received.as_slice(), INBOUND);
    drop(received);
    assert!(
        !client_send.as_slice().is_empty(),
        "receive must not mutate kernel-retained ciphertext"
    );
    server.read_tcp(&outbound).expect("server application read");
    assert_eq!(server.pull_app().expect("outbound application"), OUTBOUND);
    complete_send(&mut client, &mut client_send, outbound.len());

    server
        .send_key_update(shin::wire::handshake::KeyUpdateRequest::Requested)
        .expect("key update request");
    let mut requested = server.pull_send();
    let plain = sealed::static_plain(SECOND_OUTBOUND);
    drop(ClientTls::prepare_send(
        &mut client,
        Storage::from_raw(&mut client_send, SECOND_OUTBOUND.len()),
        plain,
    ));
    let second_outbound = client_send.as_slice().to_vec();
    assert_eq!(client_runtime.buffer_usage().send_available(), 0);

    process_empty(
        &mut client,
        &mut client_runtime,
        &mut client_send,
        &mut requested,
    );
    assert_eq!(client_send.as_slice(), second_outbound);
    server
        .read_tcp(&second_outbound)
        .expect("pre-response application read");
    assert_eq!(
        server.pull_app().expect("pre-response application"),
        SECOND_OUTBOUND
    );
    complete_send(&mut client, &mut client_send, second_outbound.len());

    let response = client_send.as_slice().to_vec();
    assert!(
        !response.is_empty(),
        "send completion must drain KeyUpdate debt"
    );
    server.read_tcp(&response).expect("KeyUpdate response read");
    complete_send(&mut client, &mut client_send, response.len());

    drop(ClientTls::graceful_close(
        &mut client,
        Storage::from_raw(&mut client_send, 0),
    ));
    assert!(
        !client_send.as_slice().is_empty(),
        "deferred control must not poison the established connection"
    );
}
