use dope::core::driver::route::KeyTag;
use dope::net::wire::{
    domain::{Bootstrap as _, Limits},
    open::{self, Runtime as _},
    send::Store as _,
};
use dope_test::alloc::Tracker;
use dope_tls::{
    config::raw::Identity,
    tls::{endpoint, protocol::Bootstrap, roles},
};
use std::sync::Arc;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn full_admission_no_alloc() {
    let slots = endpoint::Sessions::<roles::Client>::try_new(1).expect("one session slot");
    let config = endpoint::Config::client(
        Arc::new(Identity::client([7; 32]).expect("client configuration")),
        "example.com".try_into().expect("server name"),
    );
    let mut run = Bootstrap::<roles::Client>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        config.bind(&slots),
    )
    .expect("endpoint runtime");
    let first = match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
        open::Outcome::Opened(parts) => Some(parts),
        open::Outcome::Failed { .. } | open::Outcome::Unavailable(()) => None,
    }
    .expect("first client open");
    let hello = first.1.as_slice().to_vec();
    assert!(!hello.is_empty());

    let (full, activity) = Tracker::counts(|| run.open(7, |_, _, _| open::Disposition::Commit(())));
    assert!(matches!(full, open::Outcome::Unavailable(7)));
    assert_eq!(activity, [0, 0]);
    assert_eq!(first.1.as_slice(), hello);
    drop(first);
    assert!(matches!(
        run.open((), |(), wire, send| open::Disposition::Commit((wire, send))),
        open::Outcome::Opened(_)
    ));
}

#[test]
fn rejects_rebinding() {
    let pool = endpoint::Sessions::<roles::Server>::try_new(1).expect("one session slot");
    let config = Arc::new(
        Identity::from_seed(&[11; 32])
            .expect("server identity")
            .server()
            .expect("server configuration"),
    );
    let runtime = Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(config.clone()).bind(&pool),
    )
    .expect("bind storage");
    drop(runtime);

    let result = Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(config).bind(&pool),
    );
    assert!(matches!(
        result,
        Err(dope::net::Resource::Binding(
            dope::net::BindingError::AlreadyBound
        ))
    ));
}

#[test]
fn failed_binding_retries() {
    let pool = endpoint::Sessions::<roles::Server>::try_new(1).expect("one session slot");
    let config = Arc::new(
        Identity::from_seed(&[11; 32])
            .expect("server identity")
            .server()
            .expect("server configuration"),
    );
    let (result, activity) = Tracker::activity(|| {
        Tracker::fail_after(3, || {
            Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
                Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
                endpoint::Config::from(config.clone()).bind(&pool),
            )
        })
    });
    assert!(matches!(
        result,
        Err(dope::net::Resource::Queue(o3::alloc::Error::Exhausted))
    ));
    assert_eq!(activity.allocations, 3);
    assert_eq!(activity.deallocations, 3);
    assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);

    let mut runtime = Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(config).bind(&pool),
    )
    .expect("retry unbound storage");
    assert!(matches!(
        runtime.open((), |(), wire, send| open::Disposition::Commit((wire, send))),
        open::Outcome::Opened(_)
    ));
}
