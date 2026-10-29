pub mod common;

use std::{convert::Infallible, io, sync::Arc};

use common::{
    Read,
    fiber::client::Client,
    state,
    state::{name, signing_key},
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
    net::{client, error::read},
};
use dope_test::{
    harness::{peer::AcceptScript, scenario::TIMEOUT},
    reclaim::Reports,
};
use dope_tls::{
    config,
    tls::{Tls, client::Plan, endpoint, roles},
};
use o3::buffer::Source as _;
use rustls::{
    AlertDescription, HandshakeKind, client::Resumption, server::ServerSessionMemoryCache,
};
use std::io::Write as _;

#[test]
fn cloned_plan_policy() {
    let key = signing_key().expect("server identity");
    let pubkey = key.public_key();
    let mut server = key.server().expect("server config");
    server.send_tls13_tickets = 2;
    server.session_storage = ServerSessionMemoryCache::new(8);
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server = Arc::new(server);

    let mut config = config::raw::Identity::client(pubkey).expect("client config");
    config.resumption = Resumption::in_memory_sessions(16);
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let plan = Plan::new(Arc::new(config), name());
    let mut config = config::raw::Identity::client(pubkey).expect("separate client config");
    config.resumption = Resumption::in_memory_sessions(16);
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let separate = Plan::new(Arc::new(config), name());
    let mut config = config::raw::Identity::client(pubkey).expect("unmatched client config");
    config.alpn_protocols = vec![b"other".to_vec()];
    let other = Plan::new(Arc::new(config), name());

    AcceptScript::with(
        move |accept| {
            for expected in [
                Some(HandshakeKind::Full),
                Some(HandshakeKind::Resumed),
                Some(HandshakeKind::Full),
                None,
            ] {
                let socket = accept.accept()?;
                let mut socket = &socket;
                let mut tls = rustls::ServerConnection::new(Arc::clone(&server))
                    .expect("native server");
                let mut failure = None;
                while tls.is_handshaking() {
                    while tls.wants_write() {
                        assert_ne!(tls.write_tls(&mut socket)?, 0, "handshake output");
                    }
                    assert_ne!(tls.read_tls(&mut socket)?, 0, "handshake input");
                    if let Err(cause) = tls.process_new_packets() {
                        failure = Some(cause);
                        break;
                    }
                }
                if let Some(expected) = expected {
                    assert!(failure.is_none(), "handshake failure: {failure:?}");
                    assert_eq!(tls.handshake_kind(), Some(expected));
                    assert_eq!(tls.alpn_protocol(), Some(b"h2".as_slice()));
                    tls.writer().write_all(b"x")?;
                    tls.send_close_notify();
                } else {
                    assert_eq!(failure, Some(rustls::Error::NoApplicationProtocol));
                }
                while tls.wants_write() {
                    assert_ne!(tls.write_tls(&mut socket)?, 0, "terminal output");
                }
            }
            io::Result::Ok(())
        },
        |server| {
            for (plan, matched) in [
                (plan.clone(), true),
                (plan, true),
                (separate, true),
                (other, false),
            ] {
                let addr = server.addr();
                let end = endpoint::Config::from(plan);
                let plan = client::Plan::<Tcp, Tls<roles::Client>>::try_new(Capacity::fixed::<1>())
                    .expect("client storage");
                let config = Needs::from_tree(&plan)
                    .expect("client requirements")
                    .resolve::<Balanced>()
                    .expect("driver configuration");
                let mut attempt = Attempt::new();
                let exec = Executor::new(&mut attempt, config.with_queues(state::QUEUES))
                    .map_err(|cause| format!("{:?}", cause.kind()))
                    .expect("TLS executor");
                let mut reports = Reports::<1>::new(config, [Id::fixed::<0>()]);
                exec.with_plan(storage::Value::new(plan)).run(|exec| {
                    let result = exec.enter_with(|mut scope| {
                        let plan = scope.storage();
                        let Ok(wire) = plan.wire_domain().bind(end);
                        let store = plan.try_build(scope.driver().storage).expect("client port storage");
                        let handle = store.handle();
                        let mut finish = Completion::new();
                        let result = store.machine_in(wire, &mut scope, |scope| scope.driver(), |machine, scope| {
                            scope.with_quiesce(&mut finish, Client { machine }, TIMEOUT, |mut app| {
                                let result = app.block_on(dope_fiber::fiber!('_ => async move {
                                    let mut stream = handle.connect(addr).await
                                        .map_err(|cause| format!("{:?}", cause.map_ref(open::Error::cause)))
                                        .expect("TLS connect");
                                    if !matched {
                                        let cause = stream.read().await.err().expect("ALPN rejected");
                                        assert!(matches!(
                                            cause.map_ref(terminal::Error::causes),
                                            read::Read::Wire((dope_tls::Error::Tls(rustls::Error::AlertReceived(AlertDescription::NoApplicationProtocol)), None))
                                        ));
                                        return;
                                    }
                                    let mut received = Vec::new();
                                    loop {
                                        let Some(mut lease) = stream.read().await
                                            .map_err(|cause| format!("{:?}", cause.map_ref(terminal::Error::causes)))
                                            .expect("authenticated TLS read") else { break };
                                        while !lease.is_empty() {
                                            lease.drive(Ok(()), &mut Read(|head: &[u8]| {
                                                received.extend_from_slice(head);
                                                head.len()
                                            })).expect("consume response");
                                        }
                                    }
                                    assert_eq!(received, b"x");
                                }));
                                assert!(result.is_ok(), "TLS exchange completed");
                            })
                        });
                        assert!(matches!(result, Ok(Ok(()))), "client shutdown");
                    }, recovery::Policy::new(
                        |report| reports.push(report),
                        |failure: recovery::Recovery<'_, '_>| -> Infallible {
                            panic!("native recovery: {:?}", failure.cause())
                        },
                    ));
                    assert!(result.is_ok(), "client route");
                });
                assert!(reports.events().expect("native retirement").is_empty());
            }
            server.finish().expect("peer joined").expect("native TLS peer");
        },
    ).expect("native TLS peer started");
}
