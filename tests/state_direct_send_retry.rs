pub mod common;

use std::{cell::Cell, num::NonZero, sync::Arc};

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
        app::{Host, env::Bundle, receive::Borrowed},
        network::listener::{self, config::Config, conn::write, handler, topology::Layout},
        timing,
    },
    net::{link::egress, tcp::Tcp, wire::domain::Owner},
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
    reply::{Capacity, Change, Event, Mode, PREFIX, Reply, run_pair},
    state::{QUEUES, signing_key},
};

type Wire = Tls<Server>;

#[test]
fn released_direct() {
    let key = signing_key().expect("signing key");
    let pubkey = key.public_key();
    let body = b"direct reply after ciphertext release";
    let ready = Gate::new();
    let closes = Gate::new();
    let inputs = Cell::new(0);
    let writes = Cell::new(0);
    let started = Cell::new(0);
    let released = Cell::new([0; 2]);
    let opens = Trace::<_, 2>::new();
    let faults = Trace::<_, 2>::new();
    let peers = Trace::<_, 2>::new();
    let copies = Cell::new(None);
    let eofs = Cell::new(0);
    let observe = |event: Event<'_>| match event {
        Event::Open(cause) => opens.record(cause),
        Event::Wire(cause) => faults.record(cause),
        Event::Peer(cause) => peers.record(cause),
        Event::Copy(cause) => copies.set(Some(cause)),
        Event::Input(bytes) => {
            assert_eq!(bytes, b"start");
            inputs.set(inputs.get() + 1);
        }
        Event::Eof(_) => eofs.set(eofs.get() + 1),
        Event::Write(result) => {
            assert!(matches!(result, Ok(write::Outcome::Committed(()))));
            writes.set(writes.get() + 1);
        }
    };
    let capacity = |event: Change<'_>| match event {
        Change::Ready(pending) => assert!(matches!(pending, egress::Pending::Absent)),
        Change::Activated => {
            started.set(started.get() + 1);
            assert_eq!(released.get(), [0; 2], "both owners precede CQ settlement");
            assert_eq!(writes.get(), started.get());
        }
        Change::Released {
            index,
            body: returned,
            cause,
        } => {
            assert!(matches!(cause, handler::Disposition::Sent));
            assert_eq!(returned, body);
            let mut counts = released.get();
            counts[index] += 1;
            released.set(counts);
        }
    };
    let net = Config::<Tcp> {
        max_connections: 2,
        per_ip: None,
        direct_flights: 2.into(),
        bind: ([127, 0, 0, 1], 0).into(),
        backlog: socket::Backlog::fixed::<2>(),
        stream: Default::default(),
        transport: Default::default(),
        egress: egress::Config::shared(egress::Credit::fixed::<0, 0>()),
    }
    .try_prepare()
    .expect("listener capacity");
    let layout = Layout::<KeyTag<0>, Borrowed>::new(net.connections());
    let drive = Needs::from_tree(&layout)
        .and_then(|needs| needs.resolve::<timing::Throughput>())
        .expect("driver configuration");
    let mut attempt = Attempt::new();
    let exec = Executor::new(&mut attempt, drive.with_queues(QUEUES))
        .map_err(|cause| format!("{:?}", cause.kind()))
        .expect("TLS executor");
    let owner = Owner::<Wire, KeyTag<0>>::try_new(net.connections()).expect("TLS storage");
    exec.with_storage(owner).run(|exec| {
        let mut reports = Reports::<1>::new(drive, [<FrameworkTag<kind::Any> as Tag>::ROUTE]);
        let entered = exec.enter_with(
            |mut sess| {
                let targets = Cell::new([None; 2]);
                let armed = Cell::new(false);
                let store = sess.storage();
                let wire = endpoint::Config::from(Arc::new(key.server().expect("server policy")))
                    .with_send(NonZero::<usize>::MIN);
                let Ok(endpoint) = store.bind(wire);
                let init =
                    listener::Install::<KeyTag<0>, Bundle<Tcp, Wire, timing::Throughput>, _>::new(
                        net, endpoint,
                    );
                let hash = sess.hash_state(listener::Domain::for_listener(0));
                let result = init.with_driver(
                    Capacity {
                        reply: Reply {
                            body: body.to_vec(),
                            closes: closes.clone(),
                            observe: &observe,
                            mode: Mode::Close,
                        },
                        targets: &targets,
                        armed: &armed,
                        ready: ready.clone(),
                        observe: &capacity,
                    },
                    hash,
                    &mut sess,
                    session::Scope::driver,
                    |listen, sess| {
                        peer::Peer::at(listen.local_addr())
                            .with_many::<2, _, _>(
                                move |sockets| run_pair(sockets, pubkey),
                                |client| {
                                    let mut finish = Completion::new();
                                    let driven = sess.with_quiesce(
                                        &mut finish,
                                        Host::new(listen),
                                        TIMEOUT,
                                        |mut app| {
                                            let harness = fibers::Harness::new(GUARD);
                                            assert_eq!(
                                                harness
                                                    .try_wait(&mut app, &ready, 2)
                                                    .expect("establish both TLS peers"),
                                                fibers::Wait::Reached
                                            );
                                            assert_eq!(writes.get(), 0);
                                            armed.set(true);
                                            for target in targets.get() {
                                                target.expect("established peer target").wake();
                                            }
                                            assert_eq!(
                                                harness
                                                    .try_wait(&mut app, &closes, 2)
                                                    .expect("drain both direct replies"),
                                                fibers::Wait::Reached
                                            );
                                        },
                                    );
                                    assert!(driven.is_ok(), "listener shutdown");
                                    let replies = client
                                        .finish()
                                        .expect("finish native peers")
                                        .expect("TLS replies");
                                    let mut expected = PREFIX.to_vec();
                                    expected.extend_from_slice(body);
                                    for (closed, got, _) in replies {
                                        assert!(closed, "close_notify precedes TCP EOF");
                                        assert_eq!(got, expected);
                                    }
                                },
                            )
                            .expect("spawn TLS peers");
                    },
                );
                assert!(result.is_ok(), "listener installation");
            },
            recovery::Policy::new(|report| reports.push(report), common::recover),
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
    assert_eq!(inputs.get(), 2, "peers send only their readiness records");
    assert_eq!(started.get(), 2);
    assert_eq!(released.get(), [1; 2]);
    assert_eq!(closes.hits(), 2);
    assert!(opens.values().expect("open observations").is_empty());
    assert!(faults.values().expect("wire observations").is_empty());
    assert!(peers.values().expect("peer observations").is_empty());
    assert_eq!(copies.take(), None);
    assert_eq!(eofs.get(), 0);
}
