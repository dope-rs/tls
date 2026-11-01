pub mod common;

use std::{io, io::Write as _, sync::Arc, time::Duration};

use common::{Read, Signer, fiber::client::Client, state, times::Fixed};
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
use dope_fiber::{BlockOn, net::client};
use dope_test::{
    harness::{peer::AcceptScript, scenario::TIMEOUT},
    reclaim::Reports,
};
use dope_tls::{
    config::Ext as _,
    tls::{Tls, client::Plan, endpoint, roles},
};
use o3::buffer::Source as _;
use rustls::{
    ClientConfig, HandshakeKind, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, UnixTime},
};

#[test]
fn clones_resume() {
    let signer = Signer::new([9; 32]);
    let cert = CertificateDer::from(
        signer
            .certificate("host.local", rcgen::CertificateParams::default())
            .expect("signed certificate"),
    );
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("trust anchor");
    let clock = Arc::new(Fixed(UnixTime::since_unix_epoch(Duration::from_secs(
        1_735_689_600,
    ))));
    let mut config = ClientConfig::try_tls13()
        .expect("client builder")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.time_provider = clock.clone();
    let plan = Plan::new(Arc::new(config), "host.local".try_into().expect("name"));
    let mut server = ServerConfig::try_tls13()
        .expect("server builder")
        .with_no_client_auth()
        .with_single_cert(vec![cert], signer.key())
        .expect("server identity");
    server.time_provider = clock;
    let server = Arc::new(server);

    AcceptScript::with(
        move |accept| {
            let mut kinds = [None; 2];
            for kind in &mut kinds {
                let socket = accept.accept()?;
                let mut socket = &socket;
                let mut tls = rustls::ServerConnection::new(Arc::clone(&server))
                    .expect("native server connection");
                tls.complete_io(&mut socket)?;
                assert!(!tls.is_handshaking(), "authenticated handshake");
                *kind = tls.handshake_kind();
                tls.writer().write_all(b"x")?;
                tls.send_close_notify();
                while tls.wants_write() {
                    assert_ne!(tls.write_tls(&mut socket)?, 0, "TLS output progress");
                }
            }
            io::Result::Ok(kinds)
        },
        |server| {
            let addr = server.addr();
            for _ in 0..2 {
                let config = endpoint::Config::from(plan.clone());
                let fiber = client::Plan::<Tcp, Tls<roles::Client>>::try_new(Capacity::fixed::<1>())
                    .expect("client storage");
                let driver = Needs::from_tree(&fiber)
                    .expect("client requirements")
                    .resolve::<Balanced>()
                    .expect("driver configuration");
                let mut attempt = Attempt::new();
                let exec = Executor::new(&mut attempt, driver.with_queues(state::QUEUES))
                    .map_err(|cause| format!("{:?}", cause.kind()))
                    .expect("TLS executor");
                let mut reports = Reports::<1>::new(driver, [Id::fixed::<0>()]);
                exec.with_plan(storage::Value::new(fiber)).run(|exec| {
                    let result = exec.enter_with(
                        |mut scope| {
                            let fiber = scope.storage();
                            let Ok(wire) = fiber.wire_domain().bind(config);
                            let store = fiber
                                .try_build(scope.driver().storage)
                                .expect("client port storage");
                            let handle = store.handle();
                            let mut finish = Completion::new();
                            let result = store.machine_in(
                                wire,
                                &mut scope,
                                |scope| scope.driver(),
                                |machine, scope| {
                                    scope.with_quiesce(
                                        &mut finish,
                                        Client { machine },
                                        TIMEOUT,
                                        |mut app| {
                                            let result = app.block_on(dope_fiber::fiber!('_ => async move {
                                                let mut stream = handle.connect(addr).await
                                                    .map_err(|cause| format!("{:?}", cause.map_ref(open::Error::cause)))
                                                    .expect("connect TLS peer");
                                                let mut bytes = Vec::new();
                                                while let Some(mut lease) = stream.read().await
                                                    .map_err(|cause| format!("{:?}", cause.map_ref(terminal::Error::causes)))
                                                    .expect("read TLS sentinel and clean EOF")
                                                {
                                                    while !lease.is_empty() {
                                                        lease.drive(Ok(()), &mut Read(|head: &[u8]| {
                                                            bytes.extend_from_slice(head);
                                                            head.len()
                                                        })).expect("consume sentinel");
                                                    }
                                                }
                                                assert_eq!(bytes, b"x");
                                            }));
                                            assert!(result.is_ok(), "drive TLS connection");
                                        },
                                    )
                                },
                            );
                            assert!(matches!(result, Ok(Ok(()))), "client machine and shutdown");
                        },
                        recovery::Policy::new(
                            |report| reports.push(report),
                            common::recover,
                        ),
                    );
                    assert!(result.is_ok(), "client route");
                });
                assert!(
                    reports.events().expect("reclamation observations").is_empty(),
                    "unexpected reclaimed completions: {reports:?}"
                );
            }
            let kinds = server
                .finish()
                .expect("join native TLS peer")
                .expect("native TLS peer");
            assert_eq!(kinds, [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]);
        },
    )
    .expect("spawn native TLS peer");
}
