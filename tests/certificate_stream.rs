use dope_test::reclaim::Reports;
pub mod common;

use crate::common::fiber::client::Client;
use crate::common::state::{self, certs::Kind};
use dope::core::driver::{
    life::{creation::Attempt, recovery},
    route::{Id, table::conn::Capacity},
    settings::claim::Needs,
    storage,
};
use dope::manifold::timing::Balanced;
use dope::net::tcp::Tcp;
use dope::net::wire::{open, terminal};
use dope::runtime::executor::{Executor, session::Completion};
use dope_fiber::{
    BlockOn,
    net::{client::Plan, error::read},
};
use dope_test::harness::{peer::TcpScript, scenario::TIMEOUT};
use dope_tls::tls::{Tls, endpoint, roles};
use rustls::{AlertDescription, Error};
use std::convert::Infallible;
use std::sync::Arc;

#[test]
fn endpoint_reports_cause() {
    for kind in [Kind::Raw, Kind::X509] {
        let (client, _) = kind.configs().expect("client config");
        TcpScript::with(move |stream| kind.serve(stream), |server| {
        let addr = server.addr();
        let end = endpoint::Config::client(Arc::new(client), state::name());
        let plan =
            Plan::<Tcp, Tls<roles::Client>>::try_new(Capacity::fixed::<1>()).expect("client plan");
        let config = Needs::from_tree(&plan).expect("client needs").resolve::<Balanced>().expect("client configuration");
        let mut attempt = Attempt::new();
        let exec = Executor::new(&mut attempt, config.with_queues(state::QUEUES));
        assert!(exec.is_ok(), "executor creation: {:?}", exec.as_ref().err().map(|cause| cause.kind()));
        let exec = exec.ok().expect("created executor");
        let mut reports = Reports::<_>::new(config, [Id::fixed::<0>()]);
        exec.with_plan(storage::Value::new(plan)).run(|exec| {
            let result = exec.enter_with(|mut scope| {
                let plan = scope.storage();
                let Ok(wire) = plan.wire_domain().bind(end);
                let store = plan.try_build(scope.driver().storage).expect("client storage");
                let handle = store.handle();
                let mut finish = Completion::new();
                let result = store.machine_in(wire, &mut scope, |scope| scope.driver(), |machine, scope| {
                    scope.with_quiesce(&mut finish, Client { machine }, TIMEOUT, |mut app| {
                        let result = app.block_on(dope_fiber::fiber!('_ => async move {
                            let opened = handle.connect(addr).await;
                            assert!(opened.is_ok(), "client connection: {:?}", opened.as_ref().err().map(|cause| cause.map_ref(open::Error::cause)));
                            let mut stream = opened.ok().expect("connected client");
                            let cause = stream.read().await.err()
                                .expect("rejected certificate cannot publish a connection read");
                            assert!(matches!(
                                cause.map_ref(terminal::Error::causes),
                                read::Read::Wire((dope_tls::Error::Tls(error), None)) if *error == kind.error()
                            ), "certificate rejection must drain its terminal alert: {:?}", cause.map_ref(terminal::Error::causes));
                        }));
                        assert!(result.is_ok(), "TLS failure observation must finish within the bounded driver scope");
                    })
                });
                assert!(matches!(result, Ok(Ok(()))), "TLS machine must retire all connection owners");
            }, recovery::Policy::new(|report| reports.push(report), recover));
            assert!(result.is_ok(), "TLS route must finish cleanly");
        });
        assert!(
            reports.events().expect("valid native retirement").is_empty(),
            "unexpected native retirement: {reports:?}"
        );
        let cause = server.finish().expect("peer joined").expect("certificate peer");
        let expected = match kind {
            Kind::Raw => AlertDescription::AccessDenied,
            Kind::X509 => AlertDescription::UnknownCA,
        };
        assert_eq!(cause, Error::AlertReceived(expected));
    }).expect("certificate peer started");
    }
}

fn recover(failure: recovery::Recovery<'_, '_>) -> Infallible {
    panic!("native recovery: {:?}", failure.cause());
}
