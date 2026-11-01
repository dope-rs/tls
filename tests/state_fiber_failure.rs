use dope::core::driver::life::recovery;
use dope::core::driver::route::KeyTag;
use dope_tls::tls::Tls;
use dope_tls::tls::roles::Server;
type Wire = Tls<Server>;
use crate::common::fiber::Bound;
use dope::core::driver::life::creation::Attempt;
use dope::core::driver::settings::claim::Needs;
use dope::runtime::executor::session::Completion;
use dope_test::harness::scenario::TIMEOUT;
pub mod common;

use dope::core::driver::route::{FrameworkTag, Tag, kind};
use dope_test::reclaim::Reports;
use std::io::{self, Write};
use std::net::Shutdown;

use crate::common::Read;
use dope::core::{
    driver::{route::table::conn::Capacity, storage},
    io::socket,
};
use dope::manifold::network::listener;
use dope::manifold::timing::Balanced;
use dope::net::tcp::Tcp;
use dope::net::wire::terminal;
use dope::runtime::executor::Executor;
use dope_fiber::{
    BlockOn,
    net::{
        error::read,
        server::{Config, Listener, Plan},
    },
};
use dope_test::harness::peer;
use dope_tls::Error;
use o3::buffer::Source as _;

use crate::common::{
    fiber::{App, Peer},
    state::{self},
};

const BEFORE_FAILURE: &[u8] = b"authenticated-before-failure";

#[derive(Clone, Copy)]
enum Input {
    CorruptRecord,
    Truncated,
}

fn assert_end(input: Input) {
    {
        let (end, pubkey) = Peer::try_server().expect("TLS fixture initialization");
        let (bound, addr) = Bound::try_new().expect("reserve TLS listener").into_parts();
        let capacity = Capacity::fixed::<1>();
        let plan = Plan::<Wire>::try_new(capacity).expect("listener storage");
        let config = Needs::from_tree(&plan)
            .and_then(|needs| needs.resolve::<Balanced>())
            .expect("listener configuration");
        let mut attempt = Attempt::new();
        let exec = Executor::new(&mut attempt, config.with_queues(state::QUEUES))
            .map_err(|cause| format!("{:?}", cause.kind()))
            .expect("create TLS executor");
        let exec = exec.with_plan(storage::Value::new(plan));

        exec.run(|exec| {
            let mut reports = Reports::<1>::new(config, [<FrameworkTag<kind::Any> as Tag>::ROUTE]);
            let entered = exec.enter_with(
                move |mut scope| {
                    let hash = scope.hash_state(listener::Domain::DEFAULT);
                    let plan = scope.storage();
                    let store = plan.try_build(scope.driver().storage).expect("listener port must initialize");
                    let config = Config {
                        direct_flights: 1.into(),
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
                                .with(
                                    move |socket| {
                                        {
                                            let peer = Peer::establish(socket, pubkey);
                                            let mut peer = peer.expect("TLS handshake");
                                            let mut wire = peer.seal(BEFORE_FAILURE).expect("authenticated TLS record");
                                            if matches!(input, Input::CorruptRecord) {
                                                let mut bad = peer.seal(b"corrupt").expect("TLS record to corrupt");
                                                let last = (bad.last_mut())
                                                    .expect("TLS record authentication tag");
                                                *last ^= 0xff;
                                                wire.extend_from_slice(&bad);
                                            }
                                            assert!(
                                                peer.socket.write_all(&wire).is_ok(),
                                                "write terminal-case TLS records"
                                            );
                                            assert!(
                                                peer.socket.shutdown(Shutdown::Write).is_ok(),
                                                "close client write half"
                                            );
                                            if matches!(input, Input::CorruptRecord) {
                                                loop {
                                                    let read = peer.tls.read_tls(&mut peer.socket)
                                                        .expect("read server fatal alert");
                                                    assert_ne!(
                                                        read, 0,
                                                        "server closed before fatal alert"
                                                    );
                                                    match peer.tls.process_new_packets() {
                                                        Ok(_) => {}
                                                        Err(cause) => break Some(cause),
                                                    }
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                    },
                                    |client| {
                                        let mut finish = Completion::new();
                                        let driven = scope.with_quiesce(
                                &mut finish,
                                App { pool },
                                TIMEOUT,
                                |mut app| {
                                    let stream =
                                        app.block_on(dope_fiber::fiber!('_ => async move {
                                            accept.accept().await
                                        }));
                                    let stream = stream.expect("drive TLS connection accept");
                                    let mut stream = stream.ok().expect("accept TLS connection");

                                    {
                                        let plain = app.block_on(stream.read());
                                        let plain = plain.expect("drive authenticated plaintext read");
                                        let mut plain = plain
                                            .map_err(|cause| format!("{:?}", cause.map_ref(terminal::Error::causes))).expect("read authenticated plaintext")
                                            .expect(
                                                "wire failure overtook authenticated plaintext",
                                            );
                                        plain.drive(
                                            Ok(()),
                                            &mut Read(|head: &[u8]| {
                                                assert_eq!(head, BEFORE_FAILURE);
                                                head.len()
                                            }),
                                        ).expect("consume authenticated plaintext");
                                        assert!(plain.is_empty());
                                    }

                                    let result = app.block_on(stream.read());
                                    let cause = {
                                        result.expect("drive terminal read").err().expect("read must fail after authenticated plaintext")
                                    };
                                    let cause = match cause {
                                        read::Read::Wire(cause) => Some(cause),
                                        _ => None,
                                    }
                                    .expect("read must preserve the exact TLS failure");
                                    let (cause, closing) = cause.into_parts();
                                    assert!(closing.is_none(), "fatal alert sealing failed");
                                    match input {
                                        Input::CorruptRecord => assert!(matches!(
                                            cause, Error::Tls(rustls::Error::DecryptError)
                                        ), "unexpected TLS failure: {cause:?}"),
                                        Input::Truncated => assert!(matches!(
                                            cause, Error::Io(ref error)
                                                if error.kind() == io::ErrorKind::UnexpectedEof
                                        ), "unexpected TLS failure: {cause:?}"),
                                    }

                                    assert!(matches!(app.block_on(stream.read()), Ok(Ok(None))));
                                    peer::Peer::at(addr).with(
                                        move |socket| {
                                            let mut peer = Peer::establish(socket, pubkey)
                                                .expect("replacement TLS handshake");
                                            peer.try_recv().expect("replacement TLS reply")
                                        },
                                        |replacement| {
                                            let mut next = app.block_on(accept.accept())
                                                .expect("drive replacement accept")
                                                .ok().expect("capacity one must accept again");
                                            drop(stream);
                                            assert!(matches!(app.block_on(next.write_all(b"ok")), Ok(Ok(()))));
                                            assert_eq!(replacement.finish().expect("replacement TLS peer"), b"ok");
                                        },
                                    ).expect("spawn replacement TLS peer");
                                },
                            );
                                        assert!(driven.is_ok(), "drive exact TLS failure");
                                        let alert = (client.finish()).expect("finish TLS client");
                                        if matches!(input, Input::CorruptRecord) {
                                            let alert = (alert)
                                    .expect("corrupt record must receive the server fatal alert");
                                            assert_eq!(alert, rustls::Error::AlertReceived(
                                                rustls::AlertDescription::BadRecordMac,
                                            ));
                                        } else {
                                            assert!(alert.is_none());
                                        }
                                    },
                                )
                                .expect("spawn TLS client");
                        },
                    );
                    assert!(result.is_ok(), "TLS listener must be adopted");
                    assert!(rejected.is_empty(), "TLS open failed");
                },
                recovery::Policy::new(|report| reports.push(report), common::recover),
            );
            assert!(
                reports.events().expect("reclamation observations").is_empty(),
                "unexpected reclaimed completions: {reports:?}"
            );
            assert!(entered.is_ok(), "listener port storage");
        });
    }
}

#[test]
fn data_precedes_record() {
    assert_end(Input::CorruptRecord);
}

#[test]
fn data_precedes_truncation() {
    assert_end(Input::Truncated);
}
