pub mod common;

use std::{cell::Cell, convert::Infallible, net::SocketAddr, sync::Arc};

use dope::{
    core::{
        driver::{
            life::{creation::Attempt, recovery},
            route::{FrameworkTag, KeyTag, Tag, kind},
            settings::claim::Needs,
        },
        io::socket,
    },
    manifold::{
        app::{env::Bundle, receive::Borrowed},
        network::listener::{self, config::Config, conn::write, topology::Layout},
        timing,
    },
    net::{tcp::Tcp, wire::domain::Owner},
    runtime::executor::{Executor, session, session::Completion},
};
use dope_test::{
    fibers,
    harness::{
        GUARD,
        observe::Trace,
        peer,
        scenario::TIMEOUT,
        signals::{Gate, Progress as _},
    },
    reclaim::Reports,
};
use dope_tls::tls::{Tls, endpoint, roles::Server};

use common::{
    reply::{App, Event, LEN, Mode, PREFIX, Records, Reply, run_client},
    state::{QUEUES, signing_key},
};

type Wire = Tls<Server>;

#[test]
fn vectored_reply_drains() {
    let body: Vec<_> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let mut expected = PREFIX.to_vec();
    expected.extend_from_slice(&body);
    let (received, records) = run(Mode::Close, body, 16);
    assert_eq!(received, expected, "reply precedes authenticated EOF");
    assert_eq!(
        records.count,
        expected.len().div_ceil(1 << 14) + 1,
        "vectored boundaries must not create separate application records"
    );
    assert!(records.tail.is_empty(), "the final record is complete");
}

#[test]
fn shutdown_keeps_receiving() {
    let body: Vec<_> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let mut expected = PREFIX.to_vec();
    expected.extend_from_slice(&body);
    for direct in [0, 16] {
        let (received, _) = run(Mode::Local, body.clone(), direct);
        assert_eq!(received, expected);
    }
}

#[test]
fn peer_close_keeps_writing() {
    let (received, _) = run(Mode::Peer, b"after peer EOF".to_vec(), 16);
    let mut expected = PREFIX.to_vec();
    expected.extend_from_slice(b"after peer EOF");
    assert_eq!(received, expected);
}

fn run(mode: Mode, body: Vec<u8>, direct: usize) -> (Vec<u8>, Records) {
    let key = signing_key().expect("signing key");
    let pubkey = key.public_key();
    let closes = Gate::new();
    let opens = Trace::<_, 16>::new();
    let faults = Trace::<_, 16>::new();
    let peers = Trace::<_, 16>::new();
    let copies = Cell::new(None);
    let inputs = Cell::new(Vec::new());
    let eofs = Cell::new(0);
    let observe = |event: Event<'_>| match event {
        Event::Open(cause) => opens.record(cause),
        Event::Wire(cause) => faults.record(cause),
        Event::Peer(cause) => peers.record(cause),
        Event::Copy(cause) => copies.set(Some(cause)),
        Event::Input(mut bytes) => {
            let mut input = inputs.take();
            input.append(&mut bytes);
            inputs.set(input);
        }
        Event::Eof(seen) => {
            assert!(seen, "plaintext must precede EOF");
            eofs.set(eofs.get() + 1);
        }
        Event::Write(result) => assert!(matches!(result, Ok(write::Outcome::Committed(())))),
    };
    let net = Config::<Tcp> {
        max_connections: 16,
        per_ip: None,
        direct_flights: direct.into(),
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        backlog: socket::Backlog::fixed::<128>(),
        stream: Default::default(),
        transport: Default::default(),
        egress: Default::default(),
    };
    let net = net.try_prepare().expect("listener capacity");
    let layout = Layout::<KeyTag<0>, Borrowed>::new(net.connections());
    let drive = Needs::from_tree(&layout)
        .and_then(|needs| needs.resolve::<timing::Throughput>())
        .expect("driver configuration");
    let mut attempt = Attempt::new();
    let exec = Executor::new(&mut attempt, drive.with_queues(QUEUES))
        .map_err(|cause| format!("{:?}", cause.kind()))
        .expect("TLS executor");
    let owner = Owner::<Wire, KeyTag<0>>::try_new(net.connections()).expect("TLS storage");
    let mut output = None;
    exec.with_storage(owner).run(|exec| {
        let mut reports = Reports::<1>::new(drive, [<FrameworkTag<kind::Any> as Tag>::ROUTE]);
        let entered = exec.enter_with(
            |mut sess| {
                let store = sess.storage();
                let wire = endpoint::Config::from(Arc::new(key.server().expect("server policy")));
                let Ok(endpoint) = store.bind(wire);
                let init =
                    listener::Install::<KeyTag<0>, Bundle<Tcp, Wire, timing::Throughput>, _>::new(
                        net, endpoint,
                    );
                let hash = sess.hash_state(listener::Domain::for_listener(0));
                let result = init.with_driver(
                    Reply {
                        body,
                        closes: closes.clone(),
                        observe: &observe,
                        mode,
                    },
                    hash,
                    &mut sess,
                    session::Scope::driver,
                    |listen, sess| {
                        peer::Peer::at(listen.local_addr())
                            .with(
                                move |socket| run_client(socket, pubkey, mode),
                                |client| {
                                    let mut finish = Completion::new();
                                    let driven = sess.with_quiesce(
                                        &mut finish,
                                        App { listener: listen },
                                        TIMEOUT,
                                        |mut app| {
                                            assert_eq!(
                                                fibers::Harness::new(GUARD)
                                                    .try_wait(&mut app, &closes, 1)
                                                    .expect("drive TLS close"),
                                                fibers::Wait::Reached
                                            );
                                        },
                                    );
                                    assert!(driven.is_ok(), "listener shutdown");
                                    let (closed, got, records) = client
                                        .finish()
                                        .expect("finish native peer")
                                        .expect("TLS reply");
                                    assert!(closed, "close_notify must precede TCP EOF");
                                    output = Some((got, records));
                                },
                            )
                            .expect("spawn TLS peer");
                    },
                );
                assert!(result.is_ok(), "listener installation");
            },
            recovery::Policy::new(|report| reports.push(report), recover),
        );
        assert!(
            reports
                .events()
                .expect("reclamation observations")
                .is_empty(),
            "unexpected reclaimed completions: {reports:?}"
        );
        assert!(entered.is_ok(), "listener scope");
    });
    assert!(opens.values().expect("open observations").is_empty());
    assert!(faults.values().expect("wire observations").is_empty());
    assert!(peers.values().expect("peer observations").is_empty());
    assert_eq!(copies.take(), None);
    assert_eq!(closes.hits(), 1);
    assert_eq!(
        inputs.take(),
        if matches!(mode, Mode::Local) {
            b"startafter".as_slice()
        } else {
            b"start".as_slice()
        }
    );
    if matches!(mode, Mode::Peer) {
        assert_eq!(eofs.get(), 1, "receive EOF must be delivered exactly once");
    }
    output.expect("native reply")
}

fn recover(failure: recovery::Recovery<'_, '_>) -> Infallible {
    panic!("native recovery: {:?}", failure.cause())
}
