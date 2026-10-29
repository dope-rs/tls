use std::sync::Arc;

use dope::core::driver::route::KeyTag;
use dope::net::wire::{
    domain::{Bootstrap as _, Limits},
    open::{self, Runtime as _},
};
use dope_test::alloc::Tracker;
use dope_tls::{
    config::{Ext as _, raw::Identity},
    roots::Ext as _,
    tls::{client::Plan, endpoint, protocol::Bootstrap, roles},
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn root_allocation_fails() {
    let result = Tracker::fail_after(0, RootCertStore::try_webpki);
    assert!(matches!(result, Err(o3::alloc::Error::Exhausted)));
}

#[test]
fn webpki_roots_build() {
    let roots = RootCertStore::try_webpki().expect("bundled trust roots");
    assert_eq!(roots.roots, webpki_roots::TLS_SERVER_ROOTS);
    let config = ClientConfig::try_tls13()
        .expect("client builder")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client =
        rustls::ClientConnection::new(Arc::new(config), "example.com".try_into().expect("name"))
            .expect("client");
    assert!(client.is_handshaking());
}

#[test]
fn configs_stay_alive() {
    let key = Identity::from_seed(&[9; 32]).expect("server key");
    let native = Arc::new(Identity::client(key.public_key()).expect("client config"));
    let retained = Arc::downgrade(&native);
    let name = ServerName::try_from(String::from("localhost")).expect("owned server name");
    let original = Plan::new(native, name);
    let plan = original.clone();
    drop(original);

    let slots = endpoint::Sessions::<roles::Client>::try_new(1).expect("session storage");
    let mut run = Bootstrap::<roles::Client>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(plan).bind(&slots),
    )
    .expect("endpoint runtime");
    let client = match run.open((), |(), wire, _| open::Disposition::Commit(wire)) {
        open::Outcome::Opened(wire) => Some(wire),
        _ => None,
    }
    .expect("client");
    drop(run);
    assert!(retained.upgrade().is_some());
    drop(client);
    assert!(retained.upgrade().is_none());

    let native = Arc::new(key.server().expect("server config"));
    let retained = Arc::downgrade(&native);
    let slots = endpoint::Sessions::<roles::Server>::try_new(1).expect("session storage");
    let mut run = Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(native).bind(&slots),
    )
    .expect("endpoint runtime");
    let server = match run.open((), |(), wire, _| open::Disposition::Commit(wire)) {
        open::Outcome::Opened(wire) => Some(wire),
        _ => None,
    }
    .expect("server");
    drop(run);
    assert!(retained.upgrade().is_some());
    drop(server);
    assert!(retained.upgrade().is_none());
}
