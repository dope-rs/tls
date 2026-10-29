use std::sync::Arc;

use dope::{
    core::driver::route::KeyTag,
    net::wire::{
        domain::{Bootstrap as _, Limits},
        open::{self, Runtime as _},
        send::Store as _,
    },
};
use dope_test::alloc::Tracker;
use dope_tls::{
    Error,
    config::raw::Identity,
    tls::{endpoint, protocol::Bootstrap, roles},
};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn alpn_allocation_retries() {
    let sessions = endpoint::Sessions::<roles::Client>::try_new(1).expect("one session slot");
    let mut native = Identity::client([7; 32]).expect("client configuration");
    native.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = endpoint::Config::client(
        Arc::new(native),
        "example.com".try_into().expect("borrowed server name"),
    );
    let mut runtime = Bootstrap::<roles::Client>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        config.bind(&sessions),
    )
    .expect("endpoint runtime");

    for allows in 0..3 {
        let (result, activity) = Tracker::activity(|| {
            Tracker::fail_after(allows, || {
                runtime.open(allows, |_, wire, send| {
                    open::Disposition::Commit((wire, send))
                })
            })
        });
        let (context, cause) = match result {
            open::Outcome::Failed { context, cause } => Some((context, cause)),
            _ => None,
        }
        .expect("ALPN allocation must fail before opening TLS");
        assert_eq!(context, allows);
        assert!(matches!(
            cause.into_cause(),
            Error::Allocation(o3::alloc::Error::Exhausted)
        ));
        assert_eq!(
            (activity.allocations, activity.deallocations),
            (allows, allows)
        );
        assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
    }

    let parts = match runtime.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
        open::Outcome::Opened(parts) => Some(parts),
        _ => None,
    }
    .expect("retry must reuse the session and send slots");
    assert!(!parts.1.as_slice().is_empty());
}
