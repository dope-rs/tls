use std::{convert::Infallible, num::NonZero, sync::mpsc, time::Duration};

use dope::core::driver::{
    life::{creation::Attempt, recovery},
    route::{FrameworkTag, KeyTag, Tag, kind, table::conn::Capacity},
    settings::{self, Receive, claim::Needs},
    storage,
};
use dope::core::io::socket;
use dope::manifold::{network::listener, timing::Balanced};
use dope::net::{tcp::Tcp, wire::terminal};
use dope::runtime::executor::{Executor, drive, session::Completion};
use dope_fiber::{
    BlockOn,
    net::{
        error::read,
        server::{Config, Listener, Plan},
    },
    task::done::Once,
};
use dope_test::{
    alloc::Tracker,
    harness::{peer, scenario::TIMEOUT},
    reclaim::Reports,
};
use dope_tls::tls::{Tls, endpoint::layout::Staged, roles::Server};
use o3::buffer::{self, Source as _, write::consume::Consume};

use crate::common::{
    Read,
    fiber::{App, Bound, FIRST, MAX_CONNECTIONS, Peer, credit, retain::Retain},
    state,
};

pub mod common;

type Wire = Tls<Server>;
use common::fiber::credit::{AFTER_RELEASE, INDEPENDENT};

#[test]
fn provided_credit() {
    let recv = Receive::fixed::<128, 4096>();
    run_credit(b"held-first", recv, false, false, false);
}

#[test]
fn staged_credit() {
    let recv = Receive::fixed::<128, 1024>();
    run_credit(&[b's'; 16_384], recv, false, false, false);
}

#[test]
fn coalesced_credit() {
    let recv = Receive::fixed::<128, 4096>();
    run_credit(b"held-first", recv, true, false, false);
}

#[test]
fn retains_on_oom() {
    let recv = Receive::fixed::<128, 1024>();
    run_credit(&[b's'; 4096], recv, false, true, false);
}

#[test]
fn staged_final_owner() {
    let recv = Receive::fixed::<128, 1024>();
    run_credit(&[b's'; 4096], recv, false, false, true);
}

fn run_credit(body: &'static [u8], recv: Receive, joined: bool, fail: bool, escaped: bool) {
    let (end, pubkey) = Peer::try_server().expect("TLS fixture initialization");
    let end = if fail {
        end.with_growth(NonZero::<u32>::MIN)
    } else if escaped {
        end.with_staged(Staged::fixed::<0>())
    } else {
        end
    };
    let (bound, addr) = Bound::try_new().expect("reserve TLS listener").into_parts();
    let capacity = Capacity::fixed::<MAX_CONNECTIONS>();
    let plan = Plan::<Wire>::try_new(capacity).expect("listener storage");
    let config = Needs::from_tree(&plan)
        .and_then(|needs| needs.resolve::<Balanced>())
        .expect("listener configuration");
    let mut attempt = Attempt::new();
    let exec = Executor::new(
        &mut attempt,
        config
            .with_queues(state::QUEUES)
            .with_receive(recv)
            .with_domains(settings::Domain::ONE),
    )
    .map_err(|cause| format!("{:?}", cause.kind()))
    .expect("create TLS executor");
    let exec = exec.with_plan(storage::Value::new(&plan));
    let (tx, rx) = mpsc::sync_channel(0);

    exec.run(|exec| {
        let mut reports = Reports::<1>::new(config, [<FrameworkTag<kind::Any> as Tag>::ROUTE]);
        let entered = exec.enter_with(
            move |mut scope| {
                let hash = scope.hash_state(listener::Domain::DEFAULT);
                let plan = *scope.storage();
                let budget = (scope
                    .driver()
                    .storage
                    .budget(storage::Resident::bytes(4096)))
                .expect("one driver-owned resident domain");
                let store = plan
                    .try_build(scope.driver().storage)
                    .expect("listener port must initialize");
                let config = Config {
                    direct_flights: MAX_CONNECTIONS.into(),
                    bind: addr,
                    backlog: socket::Backlog::fixed::<16>(),
                    stream: Default::default(),
                    transport: Default::default(),
                    egress: Default::default(),
                    bound,
                    wire: {
                        let Ok(edge) = plan.wire_domain().bind(end);
                        edge
                    },
                };
                let mut rejected = Vec::new();
                let result = Listener::<KeyTag<0>, Tcp, Wire, _>::adopt(
                    &store,
                    config,
                    |cause| rejected.push(cause),
                    hash,
                    &mut scope,
                    |scope| scope.driver(),
                    |pool, scope| {
                        let accept = store.handle();
                        peer::Peer::at(addr)
                            .with_many::<2, _, _>(
                                move |streams| {
                                    credit::exchange(streams, pubkey, body, joined, escaped, || {
                                        rx.recv()
                                    })
                                },
                                |peers| {
                                    let mut finish = Completion::new();
                                    let driven = scope.with_quiesce(
                                        &mut finish,
                                        App { pool },
                                        TIMEOUT,
                                        |mut app| {
                                            let held =
                                                app.block_on(dope_fiber::fiber!('_ => async move {
                                                    accept.accept().await
                                                }));
                                            let held = held.expect("drive held connection accept");
                                            let mut held =
                                                held.ok().expect("accept held connection");
                                            let other =
                                                app.block_on(dope_fiber::fiber!('_ => async move {
                                                    accept.accept().await
                                                }));
                                            let other =
                                                other.expect("drive independent connection accept");
                                            let mut other =
                                                other.ok().expect("accept independent connection");

                                            let result = app.block_on(held.read());
                                            let first = result.expect("drive first record read");
                                            let mut first = first
                                                .map_err(|cause| {
                                                    format!(
                                                        "{:?}",
                                                        cause.map_ref(terminal::Error::causes)
                                                    )
                                                })
                                                .expect("read first TLS record")
                                                .expect("peer must supply first record");
                                            if joined {
                                                let ((), alloc) = Tracker::usage(|| {
                                                    assert_eq!(
                                                        buffer::Source::remaining(&*first),
                                                        FIRST.len() + body.len()
                                                    );
                                                    let start =
                                                        AsRef::<[u8]>::as_ref(&*first).as_ptr();
                                                    assert!(
                                                        buffer::Read::as_slice(
                                                            &buffer::Complete::view(&*first),
                                                        )
                                                        .starts_with(FIRST),
                                                        "coalesced plaintext keeps its prefix",
                                                    );
                                                    assert_eq!(
                                                        buffer::Source::remaining(&*first),
                                                        FIRST.len() + body.len()
                                                    );
                                                    assert_eq!(
                                                        AsRef::<[u8]>::as_ref(&*first).as_ptr(),
                                                        start
                                                    );
                                                    Consume::try_consume(&mut first, FIRST.len())
                                                        .expect("first coalesced prefix");
                                                    assert_eq!(
                                                        buffer::Source::remaining(&*first),
                                                        body.len()
                                                    );
                                                    let next = buffer::Complete::view(&*first);
                                                    let next = buffer::Read::as_slice(&next);
                                                    assert_eq!(next, body);
                                                });
                                                assert_eq!(alloc, (0, 0));
                                            }
                                            first
                                                .drive(
                                                    Ok(()),
                                                    &mut Read(|head: &[u8]| {
                                                        assert_eq!(head, body);
                                                        0
                                                    }),
                                                )
                                                .expect("observe held plaintext");
                                            assert!(tx.send(()).is_ok(), "release clients");

                                            if escaped {
                                                let saved = first
                                                    .drive(None, &mut Retain(&budget))
                                                    .expect("staged head")
                                                    .expect("retain staged backing")
                                                    .try_owned()
                                                    .expect("staged backing owns its pool slot");
                                                drop(first);
                                                assert!(
                                                    tx.send(()).is_ok(),
                                                    "both peers sent before receive resumes"
                                                );
                                                assert!(matches!(
                                                    app.drive_for(
                                                        Duration::from_millis(50),
                                                        Once::new(other.read()),
                                                    ),
                                                    Err(drive::Error::Timeout)
                                                ));
                                                assert_eq!(saved.as_slice(), body);
                                                drop(saved);
                                                for (stream, expected) in [
                                                    (&mut other, INDEPENDENT),
                                                    (&mut held, AFTER_RELEASE),
                                                ] {
                                                    let mut next = app
                                                        .drive_for(
                                                            TIMEOUT,
                                                            Once::new(stream.read()),
                                                        )
                                                        .expect("released stage resumes receive")
                                                        .map_err(|cause| {
                                                            format!(
                                                                "{:?}",
                                                                cause.map_ref(
                                                                    terminal::Error::causes
                                                                )
                                                            )
                                                        })
                                                        .expect("receive after final owner drop")
                                                        .expect("peer record");
                                                    next.drive(
                                                        Ok(()),
                                                        &mut Read(|head: &[u8]| {
                                                            assert_eq!(head, expected);
                                                            head.len()
                                                        }),
                                                    )
                                                    .expect("consume resumed peer record");
                                                }
                                                assert!(matches!(
                                                    app.block_on(held.write_all(b"held-ok")),
                                                    Ok(Ok(()))
                                                ));
                                                assert!(matches!(
                                                    app.block_on(
                                                        other.write_all(b"independent-ok")
                                                    ),
                                                    Ok(Ok(()))
                                                ));
                                                return;
                                            }

                                            let result = if fail {
                                                Tracker::fail_after(0, || {
                                                    app.block_on(other.read())
                                                })
                                            } else {
                                                app.block_on(other.read())
                                            };
                                            let probe =
                                                result.expect("drive independent record read");
                                            if fail {
                                                let cause = match probe {
                                                    Err(read::Read::Wire(cause)) => Some(cause),
                                                    _ => None,
                                                }
                                                .expect("exact receive pool allocation failure");
                                                assert!(matches!(
                                                    cause.into_parts(),
                                                    (
                                                        dope_tls::Error::Allocation(
                                                            o3::alloc::Error::Exhausted
                                                        ),
                                                        None
                                                    )
                                                ));
                                                assert_eq!(AsRef::<[u8]>::as_ref(&*first), body);
                                            } else {
                                                let probe = probe
                                                    .map_err(|cause| {
                                                        format!(
                                                            "{:?}",
                                                            cause.map_ref(terminal::Error::causes)
                                                        )
                                                    })
                                                    .expect("read independent TLS record")
                                                    .expect("peer must supply independent record");
                                                let ((), alloc) = Tracker::usage(move || {
                                                    let mut probe = probe;
                                                    probe
                                                        .drive(
                                                            Ok(()),
                                                            &mut Read(|head: &[u8]| {
                                                                assert_eq!(head, INDEPENDENT);
                                                                head.len()
                                                            }),
                                                        )
                                                        .expect("consume independent plaintext");
                                                    assert!(probe.is_empty());
                                                });
                                                assert_eq!(alloc, (0, 0));
                                            }

                                            let (saved, alloc) = Tracker::usage(|| {
                                                assert_eq!(
                                                    buffer::Read::as_slice(
                                                        &buffer::Complete::view(&*first),
                                                    ),
                                                    body,
                                                    "the receive owner lends its current head",
                                                );
                                                assert_eq!(
                                                    buffer::Source::remaining(&*first),
                                                    body.len(),
                                                    "the lent head is not consumed"
                                                );
                                                assert_eq!(AsRef::<[u8]>::as_ref(&*first), body);
                                                Consume::try_consume(&mut first, 2)
                                                    .expect("two bytes fit the owned current head");
                                                assert_eq!(
                                                    buffer::Source::remaining(&*first),
                                                    body.len() - 2
                                                );
                                                assert_eq!(
                                                    buffer::Read::as_slice(
                                                        &buffer::Complete::view(&*first),
                                                    ),
                                                    &body[2..],
                                                );
                                                let saved = first.drive(None, &mut Retain(&budget));
                                                assert!(first.is_empty());
                                                assert!(
                                                    buffer::Read::as_slice(
                                                        &buffer::Complete::view(&*first),
                                                    )
                                                    .is_empty()
                                                );
                                                assert_eq!(
                                                    Consume::try_consume(&mut first, 0,),
                                                    Ok(()),
                                                );
                                                drop(first);
                                                saved
                                            });
                                            assert_eq!(alloc, (0, 0));
                                            let saved = (saved)
                                                .expect("the nonempty suffix retains its owner")
                                                .expect("retain admitted plaintext owner");
                                            assert_eq!(saved.as_slice(), &body[2..]);
                                            if body.len()
                                                > recv.buffer_len().into_nonzero().get() as usize
                                            {
                                                assert_eq!(
                                                    budget.resident(),
                                                    0,
                                                    "staged pool backing is already owned"
                                                );
                                            }
                                            let result = app.block_on(held.read());
                                            let next = result.expect("drive resumed record read");
                                            let next = next
                                                .map_err(|cause| {
                                                    format!(
                                                        "{:?}",
                                                        cause.map_ref(terminal::Error::causes)
                                                    )
                                                })
                                                .expect("read resumed TLS record")
                                                .expect("peer must supply resumed record");
                                            let ((), alloc) = Tracker::usage(move || {
                                                let mut next = next;
                                                next.drive(
                                                    Ok(()),
                                                    &mut Read(|head: &[u8]| {
                                                        assert_eq!(head, AFTER_RELEASE);
                                                        head.len()
                                                    }),
                                                )
                                                .expect("consume resumed plaintext");
                                                assert!(next.is_empty());
                                            });
                                            assert_eq!(alloc, (0, 0));

                                            assert_eq!(
                                                saved.as_slice(),
                                                &body[2..],
                                                "resuming preserves the retained owner"
                                            );
                                            let ((), alloc) = Tracker::usage(|| drop(saved));
                                            assert_eq!(alloc, (0, 0));
                                            assert_eq!(
                                                budget.resident(),
                                                0,
                                                "last owner returns resident credit"
                                            );

                                            assert!(matches!(
                                                app.block_on(held.write_all(b"held-ok")),
                                                Ok(Ok(()))
                                            ));
                                            if !fail {
                                                assert!(matches!(
                                                    app.block_on(
                                                        other.write_all(b"independent-ok")
                                                    ),
                                                    Ok(Ok(()))
                                                ));
                                            }
                                        },
                                    );
                                    assert!(driven.is_ok(), "drive retained credit");
                                    let (reply, other) = peers
                                        .finish()
                                        .expect("finish TLS clients")
                                        .expect("TLS peer exchange");
                                    assert_eq!(reply, b"held-ok");
                                    if fail {
                                        assert!(
                                            other.is_err(),
                                            "failed receive closes its connection"
                                        );
                                    } else {
                                        assert_eq!(
                                            other.expect("receive independent reply"),
                                            b"independent-ok"
                                        );
                                    }
                                },
                            )
                            .expect("spawn TLS clients");
                    },
                );
                assert!(result.is_ok(), "TLS listener must be adopted");
                assert!(rejected.is_empty(), "TLS open failed");
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
        assert!(entered.is_ok(), "listener port storage");
    });
}

fn recover(failure: recovery::Recovery<'_, '_>) -> Infallible {
    panic!("native recovery: {:?}", failure.cause())
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
