use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use dope_net::wire::buffered::Buffered;
use dope_tls::clock::WallClock;
use dope_tls::state::{
    State,
    sessions::{Client, Server},
};
use dope_tls::tls::ClientSetup;
use shin::crypto::sig::SigningKey;
use shin::server::Shard;
use shin::server::config::{CertSource, Config, ConnectionConfig, NoClientAuth, NoGuard};

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation() {
    let _ = COUNTING.try_with(|counting| {
        if counting.get() {
            let _ = ALLOCATIONS.try_with(|allocations| {
                allocations.set(allocations.get() + 1);
            });
        }
    });
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn measured<T>(run: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATIONS.with(|allocations| allocations.set(0));
    COUNTING.with(|counting| counting.set(true));
    let output = run();
    COUNTING.with(|counting| counting.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    (output, allocations)
}

#[test]
fn validated_client_setup_repeats_without_allocating() {
    let mut setup = ClientSetup::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: [7; 32],
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap();

    let (_, allocations) = measured(|| {
        for _ in 0..1024 {
            drop(setup.for_next_dial());
        }
    });

    assert_eq!(allocations, 0);
}

fn pump(
    client: &mut State<Client>,
    server: &mut State<Server>,
    shard: &mut Shard<NoGuard, NoClientAuth>,
) -> usize {
    let mut received = 0;
    for _ in 0..16 {
        let client_wire = client.pending_send_slice();
        let client_len = client_wire.len();
        if client_len != 0 {
            server
                .read_tcp(client_wire, shard, |plaintext| {
                    received += plaintext.len();
                })
                .unwrap();
            client.consume_pending_send(client_len).unwrap();
        }

        let server_wire = server.pending_send_slice();
        let server_len = server_wire.len();
        if server_len != 0 {
            client
                .read_tcp(server_wire, |plaintext| {
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
fn constructed_shin_state_handshake_and_records_allocate_nothing() {
    let signing_key = SigningKey::from_seed(&[7; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut shard = Shard::new(Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
    let mut server = State::<Server>::new(ConnectionConfig {
        transport_params: Vec::new(),
    })
    .unwrap();
    let mut client = State::<Client>::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap();

    let (_, handshake_allocations) = measured(|| pump(&mut client, &mut server, &mut shard));

    assert!(client.is_established());
    assert!(server.is_established());
    assert_eq!(handshake_allocations, 0);

    let (received, record_allocations) = measured(|| {
        client
            .write_app(b"allocation-free application record")
            .unwrap();
        pump(&mut client, &mut server, &mut shard)
    });

    assert_eq!(received, b"allocation-free application record".len());
    assert_eq!(record_allocations, 0);
}

#[test]
fn complete_application_record_needs_no_scratch_lease() {
    let signing_key = SigningKey::from_seed(&[11; 32]).unwrap();
    let server_pubkey = *signing_key.pubkey().unwrap();
    let mut shard = Shard::new(Config {
        source: CertSource::RawPublicKey { signing_key },
        alpn_protocols: Vec::new(),
        ticket_keys: None,
    });
    let runtime = Buffered::try_fixed(1, 64 * 1024, 0, 1).unwrap();
    let pool = runtime.scratch_pool();
    let mut server = State::<Server>::with_runtime(
        ConnectionConfig {
            transport_params: Vec::new(),
        },
        WallClock::System,
        &runtime,
    )
    .unwrap();
    let mut client = State::<Client>::new(shin::client::config::Config {
        verifier: shin::client::config::Verifier::RawPublicKey {
            expected_pubkey: server_pubkey,
        },
        transport_params: Vec::new(),
        alpn_protocols: Vec::new(),
        resumption: None,
        enable_early_data: false,
    })
    .unwrap();

    for _ in 0..16 {
        let mut client_wire = client.pending_send_slice().to_vec();
        client.consume_pending_send(client_wire.len()).unwrap();
        if !client_wire.is_empty() {
            let (_, ok) = server.read_tcp_in_place(&mut client_wire, &mut shard);
            assert!(ok);
        }

        let server_wire = server.pending_send_slice().to_vec();
        server.consume_pending_send(server_wire.len()).unwrap();
        if !server_wire.is_empty() {
            client.read_tcp(&server_wire, |_| {}).unwrap();
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
    assert_eq!(pool.available(), 1);

    client.write_app(b"direct without scratch").unwrap();
    let mut wire = client.pending_send_slice().to_vec();
    client.consume_pending_send(wire.len()).unwrap();
    let held = pool.try_acquire().unwrap();
    assert_eq!(pool.available(), 0);

    let (chunks, ok) = server.read_tcp_in_place(&mut wire, &mut shard);
    assert!(ok);
    assert_eq!(
        chunks.flatten().copied().collect::<Vec<_>>(),
        b"direct without scratch"
    );
    assert_eq!(pool.available(), 0);

    drop(held);
    assert_eq!(pool.available(), 1);
}
