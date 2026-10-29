use dope::core::driver::route::KeyTag;
use dope_tls::tls::Tls;
use dope_tls::tls::roles::Server;
type Wire = Tls<Server>;
use crate::common::fiber::Bound;
use dope::core::driver::life::creation::Attempt;
use dope::core::driver::life::recovery;
use dope::core::driver::settings::claim::Needs;
use dope::runtime::executor::session::Completion;
use dope_test::harness::scenario::TIMEOUT;
use std::convert::Infallible;
use std::iter;
pub mod common;

use dope::core::driver::route::{FrameworkTag, Tag, kind};
use dope_test::reclaim::Reports;
use std::io::Write;

use dope::core::{
    driver::{route::table::conn::Capacity, storage},
    io::socket,
};
use dope::manifold::network::listener;
use dope::manifold::timing::Balanced;
use dope::net::tcp::Tcp;
use dope::net::wire::terminal;
use dope::runtime::executor::Executor;
use dope_fiber::BlockOn;
use dope_fiber::net::server::{Config, Listener, Plan};
use dope_test::harness::peer;
use o3::buffer::Source as _;

use crate::common::{Read, state};

use crate::common::fiber::*;

fn run_client(socket: &peer::Stream<'_>, pubkey: [u8; 32]) -> Vec<u8> {
    let mut peer = Peer::establish(socket, pubkey).expect("TLS handshake");
    peer.tls
        .refresh_traffic_keys()
        .expect("refresh client traffic keys");
    let mut wire = peer.seal(FIRST).expect("first TLS record");
    wire.extend_from_slice(&peer.seal(SECOND).expect("second TLS record"));
    for _ in 0..TAIL_RECORDS {
        wire.extend_from_slice(&peer.seal(b"x").expect("retained TLS tail"));
    }
    peer.socket.write_all(&wire).expect("write TLS records");
    peer.try_recv().expect("receive TLS reply")
}

#[test]
fn records_share_cursors() {
    {
        let (end, pubkey) = Peer::try_server().expect("TLS fixture initialization");
        let (bound, addr) = Bound::try_new().expect("reserve TLS listener").into_parts();
        let capacity = Capacity::fixed::<MAX_CONNECTIONS>();
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
            let mut reports =
                Reports::<1>::new(config, [<FrameworkTag<kind::Any> as Tag>::ROUTE]);
            let entered = exec.enter_with(move |mut scope| {
                let hash = scope.hash_state(listener::Domain::DEFAULT);
                let plan = scope.storage();
                let store = plan.try_build(scope.driver().storage).expect("listener port must initialize");
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
                        peer::Peer::at(addr).with(move |socket| run_client(socket, pubkey), |client| {
                        let mut finish = Completion::new();
                        let data = scope
                            .with_quiesce(&mut finish, App { pool }, TIMEOUT, |mut app| {
                                let stream = app.block_on(dope_fiber::fiber!('_ => async move {
                                    accept.accept().await
                                }))?;
                                let stream = stream.ok().expect("accept TLS connection");
                                app.block_on(dope_fiber::fiber!('_ => async move {
                                    let mut stream = stream;
                                    let want = FIRST.len() + SECOND.len() + TAIL_RECORDS;
                                    let mut data = Vec::with_capacity(want);
                                    while data.len() < want {
                                        let lease = stream.read().await;
                                        let mut lease = lease
                                            .map_err(|cause| format!("{:?}", cause.map_ref(terminal::Error::causes))).expect("read TLS plaintext")
                                            .expect("peer must supply retained TLS plaintext");
                                        while !lease.is_empty() && data.len() < want {
                                            let take = (data.len() % 3 + 1).min(want - data.len());
                                            lease.drive(Ok(()), &mut Read(|head: &[u8]| {
                                                let amount = take.min(head.len());
                                                data.extend_from_slice(&head[..amount]);
                                                amount
                                            })).expect("consume TLS plaintext");
                                        }
                                    }
                                    let written = stream.write_all(b"!").await;
                                    assert!(written.is_ok(), "write TLS reply");
                                    data
                                }))
                            });
                        let data = data.expect("enter retained plaintext scenario").expect("drive retained plaintext");

                        let mut want = FIRST.to_vec();
                        want.extend_from_slice(SECOND);
                        want.extend(iter::repeat_n(b'x', TAIL_RECORDS));
                        assert_eq!(data, want);
                        let reply = (client.finish()).expect("finish TLS client");
                        assert_eq!(reply, b"!");
                        }).expect("spawn TLS client");
                    },
                );
                assert!(result.is_ok(), "TLS listener must be adopted");
                assert!(rejected.is_empty(), "TLS open failed");
            }, recovery::Policy::new(|report| reports.push(report), recover));
            assert!(
                reports.events().expect("reclamation observations").is_empty(),
                "unexpected reclaimed completions: {reports:?}"
            );
            assert!(entered.is_ok(), "listener port storage");
        });
    }
}

fn recover(failure: recovery::Recovery<'_, '_>) -> Infallible {
    panic!("native recovery: {:?}", failure.cause())
}
