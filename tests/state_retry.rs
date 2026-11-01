use std::{
    io::{self, Read as _, Write as _},
    sync::Arc,
};

use dope::core::driver::{
    life::{creation::Attempt, recovery},
    route::{Id, table::conn::Capacity},
    settings::claim::Needs,
    storage,
};
use dope::manifold::timing::Balanced;
use dope::net::{
    tcp::Tcp,
    wire::{open, terminal},
};
use dope::runtime::executor::{Executor, session::Completion};
use dope_fiber::{
    BlockOn,
    net::{client::Plan, error::read},
};
use dope_test::{
    harness::{peer::AcceptScript, scenario::TIMEOUT},
    reclaim::Reports,
};
use dope_tls::{
    config::raw::Identity,
    rustls,
    tls::{Tls, endpoint, roles},
};
use o3::buffer::Source as _;

pub mod common;
use common::{
    Read,
    fiber::client::{ACK, Client, KEY_SEED, PING, PONG},
    state,
};

#[test]
fn reconnects() {
    for mutual in [false, true] {
        let server = Identity::from_seed(&KEY_SEED).expect("server identity");
        let client = Identity::from_seed(&[0x6b; 32]).expect("client identity");
        let pin = mutual.then(|| client.public_key());
        let config = if mutual {
            client.mutual(server.public_key())
        } else {
            Identity::client(server.public_key())
        }
        .expect("client policy");
        let config = endpoint::Config::client(Arc::new(config), state::name());

        AcceptScript::with(
            move |accept| {
                for _ in 0..2 {
                    let socket = accept.accept()?;
                    let mut socket = &socket;
                    let key = Identity::from_seed(&KEY_SEED).expect("server identity");
                    let config = match pin {
                        Some(pin) => key.server_auth(pin),
                        None => key.server(),
                    }
                    .expect("server policy");
                    let mut tls = rustls::ServerConnection::new(Arc::new(config))
                        .expect("native server connection");
                    let mut got = Vec::new();
                    let mut replied = false;
                    for _ in 0..64 {
                        while tls.wants_write() {
                            assert_ne!(tls.write_tls(&mut socket)?, 0, "TLS output progress");
                        }
                        match tls.reader().read_to_end(&mut got) {
                            Ok(_) => {}
                            Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => {}
                            Err(cause) => return Err(cause),
                        }
                        if !replied && got.len() >= PING.len() {
                            assert_eq!(got, PING);
                            tls.refresh_traffic_keys().expect("request key update");
                            tls.writer().write_all(PONG)?;
                            replied = true;
                            continue;
                        }
                        if got.len() == PING.len() + ACK.len() {
                            break;
                        }
                        assert_ne!(tls.read_tls(&mut socket)?, 0, "client closed before reply");
                        tls.process_new_packets().expect("process client TLS records");
                    }
                    assert_eq!(got, [PING, ACK].concat());
                }
                io::Result::Ok(())
            },
            |server| {
                let addr = server.addr();
                let plan = Plan::<Tcp, Tls<roles::Client>>::try_new(Capacity::fixed::<1>())
                    .expect("client storage");
                let needs = Needs::from_tree(&plan).expect("client requirements");
                let driver = needs.resolve::<Balanced>().expect("driver configuration");
                let mut attempt = Attempt::new();
                let exec = Executor::new(&mut attempt, driver.with_queues(state::QUEUES))
                    .map_err(|cause| format!("{:?}", cause.kind()))
                    .expect("TLS executor");
                let mut reports = Reports::<1>::new(driver, [Id::fixed::<0>()]);
                exec.with_plan(storage::Value::new(plan)).run(|exec| {
                    let result = exec.enter_with(|mut scope| {
                        let plan = scope.storage();
                        let Ok(wire) = plan.wire_domain().bind(config);
                        let store = plan.try_build(scope.driver().storage).expect("client port storage");
                        let handle = store.handle();
                        let mut finish = Completion::new();
                        let result = store.machine_in(wire, &mut scope, |scope| scope.driver(), |machine, scope| {
                            scope.with_quiesce(&mut finish, Client { machine }, TIMEOUT, |mut app| {
                                for _ in 0..2 {
                                    let stream = app.block_on(dope_fiber::fiber!('_ => async move {
                                        handle.connect(addr).await
                                    }));
                                    let mut stream = stream.expect("drive TLS connect")
                                        .map_err(|cause| format!("{:?}", cause.map_ref(open::Error::cause)))
                                        .expect("connect TLS peer");
                                    let result = app.block_on(dope_fiber::fiber!('_ => async move {
                                        assert!(stream.write_all(PING).await.is_ok(), "write request");
                                        let mut bytes = Vec::with_capacity(PONG.len());
                                        while bytes.len() < PONG.len() {
                                            let lease = stream.read().await;
                                            let mut lease = lease
                                                .map_err(|cause| format!("{:?}", cause.map_ref(terminal::Error::causes)))
                                                .expect("read TLS reply")
                                                .expect("peer reply");
                                            while !lease.is_empty() {
                                                lease.drive(Ok(()), &mut Read(|head: &[u8]| {
                                                    bytes.extend_from_slice(head);
                                                    head.len()
                                                })).expect("consume reply");
                                            }
                                        }
                                        assert_eq!(bytes, PONG);
                                        assert!(stream.write_all(ACK).await.is_ok(), "write after key update");
                                        let tail = stream.read().await;
                                        let cause = match tail {
                                            Err(read::Read::Wire(cause)) => Some(cause),
                                            _ => None,
                                        }.expect("abrupt native peer EOF must preserve truncation");
                                        let (cause, closing) = cause.into_parts();
                                        assert!(closing.is_none());
                                        assert!(matches!(cause, dope_tls::Error::Io(cause)
                                            if cause.kind() == io::ErrorKind::UnexpectedEof));
                                    }));
                                    assert!(result.is_ok(), "drive TLS round trip");
                                }
                            })
                        });
                        assert!(matches!(result, Ok(Ok(()))), "client machine and shutdown");
                    }, recovery::Policy::new(
                        |report| reports.push(report),
                        common::recover,
                    ));
                    assert!(reports.events().expect("reclamation observations").is_empty(),
                        "unexpected reclaimed completions: {reports:?}");
                    assert!(result.is_ok(), "client route");
                });
                server.finish().expect("join native TLS peer").expect("native TLS peer");
            },
        )
        .expect("spawn native TLS peer");
    }
}
