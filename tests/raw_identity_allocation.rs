use dope_test::alloc::Tracker;
use dope_tls::{Error, config::raw::Identity};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn identity_alloc_fails() {
    let seed = [11; 32];
    let identity = Identity::from_seed(&seed).expect("initialize native key parsing");
    let public = identity.public_key();
    drop(identity);

    let (identity, count) = Tracker::count(|| Identity::from_seed(&seed));
    drop(identity.expect("measure complete identity construction"));
    let first = count
        .checked_sub(3)
        .expect("three final ownership allocations");
    for allows in [first, first + 1] {
        let (result, activity) =
            Tracker::activity(|| Tracker::fail_after(allows, || Identity::from_seed(&seed)));
        assert!(matches!(
            result,
            Err(Error::Allocation(o3::alloc::Error::Exhausted))
        ));
        assert_eq!(
            (activity.allocations, activity.deallocations),
            (allows, allows)
        );
        assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
    }

    let identity = Identity::from_seed(&seed).expect("retry identity construction");
    assert_eq!(identity.public_key(), public);
}

#[test]
fn configs_reclaim_allocations() {
    let (_, activity) = Tracker::activity(|| {
        let identity = Identity::from_seed(&[17; 32]).expect("client identity");
        let public = identity.public_key();
        identity.mutual(public).expect("mutual client config");

        Identity::from_seed(&[17; 32])
            .expect("server identity")
            .server_auth(public)
            .expect("mutual server config");
    });
    assert_eq!(activity.allocations, activity.deallocations);
    assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
}
