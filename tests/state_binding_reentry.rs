pub mod common;

use std::sync::Arc;

use common::native::reentry::{CONTEXT, Context, Reentrant};
use dope::{
    core::driver::route::KeyTag,
    net::{
        BindingError, Resource,
        wire::domain::{Bootstrap as _, Limits},
    },
};
use dope_test::alloc::Tracker;
use dope_tls::{
    config::raw::Identity,
    tls::{endpoint, protocol::Bootstrap, roles},
};

#[global_allocator]
static ALLOCATOR: Reentrant = Reentrant;

#[test]
fn rejects_reentry() {
    let config = Arc::new(
        Identity::from_seed(&[11; 32])
            .expect("server identity")
            .server()
            .expect("server configuration"),
    );
    // First pool allocation and the completion callback's waiter allocation.
    for after in [0, 3] {
        let sessions = endpoint::Sessions::try_new(1).expect("one session slot");
        CONTEXT.with_borrow_mut(|owner| {
            *owner = Some(Context {
                sessions,
                config: config.clone(),
            });
        });

        let ((rejected, inner), activity) = Tracker::activity(|| {
            let observed = CONTEXT.with_borrow(|owner| {
                let owner = owner.as_ref().expect("binding context");
                let (outer, inner) = Reentrant::on_alloc(after, || {
                    Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
                        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
                        endpoint::Config::from(owner.config.clone()).bind(&owner.sessions),
                    )
                });
                (
                    matches!(outer, Err(Resource::Binding(BindingError::AlreadyBound))),
                    inner,
                )
            });
            CONTEXT.with_borrow_mut(|owner| drop(owner.take()));
            observed
        });

        assert!(matches!(inner, Some(Ok(()))), "inner binding: {inner:?}");
        assert!(rejected, "the inner binding already published its pools");
        assert_eq!(activity.allocations, activity.deallocations);
        assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
    }
    drop(config);
}
