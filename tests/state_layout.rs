use dope_tls::tls::Tls;
use dope_tls::tls::roles::Server;
type Wire = Tls<Server>;
use dope_tls::{
    config::raw::Identity,
    tls::{endpoint, protocol::Bootstrap},
};
use std::{num::NonZero, sync::Arc};

use dope::net::wire::receive::mode::Disabled;
use std::mem;

use dope::core::driver::receive::credit;
use dope::net::wire::{
    self,
    domain::{Bootstrap as _, Limits},
    receive,
};
use dope_tls::tls::endpoint::layout;

const CONNECTIONS: usize = 1_024;
const RETAINED: usize = 4_096;
const MAX_PLAIN: usize = 16_384;
const STAGING: usize = 24_837;

#[test]
fn preserves_credit() {
    use receive::{Chunk, Policy};

    assert_eq!(
        mem::size_of::<Chunk<'static, 'static, Wire, Disabled>>(),
        mem::size_of::<<<Wire as wire::Spec>::Receive as Policy<Wire>>::Cursor<'static, 'static>>()
    );
    assert_eq!(
        mem::size_of::<Chunk<'static, 'static, Wire>>(),
        mem::size_of::<(
            <<Wire as wire::Spec>::Receive as Policy<Wire>>::Cursor<'static, 'static>,
            credit::Return<'static>,
        )>()
    );
    assert_eq!(
        mem::size_of::<Option<Chunk<'static, 'static, Wire>>>(),
        mem::size_of::<
            Option<(
                <<Wire as wire::Spec>::Receive as Policy<Wire>>::Cursor<'static, 'static>,
                credit::Return<'static>,
            )>,
        >()
    );
    assert_eq!(
        mem::size_of::<dope_fiber::net::read::Lease<'static, 'static, 'static, Wire>>(),
        mem::size_of::<Chunk<'static, 'static, Wire>>()
    );
}

#[test]
fn default_bound_is_exact() {
    let limits = Limits::fixed::<CONNECTIONS, RETAINED, 0, { 64 * 1024 }>();
    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let end = endpoint::Config::from(Arc::new(config));
    let layout = end.plan().layout(limits);
    let layout = layout.expect("default endpoint layout must be representable");

    assert_eq!(layout.recv_slots(), 65);
    assert_eq!(layout.send_slots(), 128);
    assert_eq!(layout.recv_cap(), MAX_PLAIN);
    assert_eq!(layout.send_cap(), STAGING);
    assert_eq!(layout.payload(), 65 * MAX_PLAIN + 128 * STAGING);
    assert_eq!(layout.payload(), 4_244_096);
}

#[test]
fn budgets_are_independent() {
    let limits = Limits::fixed::<CONNECTIONS, RETAINED, 0, { 64 * 1024 }>();
    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let end = endpoint::Config::from(Arc::new(config));
    let result = end
        .with_staged(layout::Staged::fixed::<17>())
        .with_send(NonZero::<usize>::MIN.saturating_add(22))
        .plan()
        .layout(limits);
    let split = result.expect("explicit split budgets must be representable");
    assert_eq!(split.recv_slots(), 18);
    assert_eq!(split.send_slots(), 23);
    assert_eq!(split.payload(), 18 * MAX_PLAIN + 23 * STAGING);

    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let end = endpoint::Config::from(Arc::new(config));
    let result = end
        .with_staged(layout::Staged::fixed::<{ (CONNECTIONS * 2) as u32 }>())
        .with_send(NonZero::<usize>::MAX)
        .plan()
        .layout(limits);
    let capped = result.expect("independent budgets must fit their domains");
    assert_eq!(capped.recv_slots(), (CONNECTIONS * 2 + 1) as u32);
    assert_eq!(capped.send_slots(), CONNECTIONS as u32);
}

#[test]
fn resident_sets_slots() {
    const BYTES: usize = 16 * 1024 * 1024;
    let slots = BYTES.div_ceil(MAX_PLAIN);
    let limits = Limits::fixed::<1, 1, BYTES, { 64 * 1024 }>();
    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let end = endpoint::Config::from(Arc::new(config));
    let layout = end.plan().layout(limits);
    let layout = layout.expect("resident receive budget must be representable");

    assert_eq!(slots, 1_024);
    assert_eq!(layout.recv_slots(), (slots + 1) as u32);
    assert_eq!(layout.send_slots(), 1);
    assert_eq!(layout.payload(), (slots + 1) * MAX_PLAIN + STAGING);
}

#[test]
fn zero_staged_keeps_one() {
    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let end = endpoint::Config::from(Arc::new(config));
    let result = end
        .with_staged(layout::Staged::fixed::<0>())
        .plan()
        .layout(Limits::fixed::<CONNECTIONS, 0, 0, { 64 * 1024 }>());
    let staged = result.expect("the active record cursor must remain available");
    assert_eq!(staged.recv_slots(), 1);
}

#[test]
fn rejects_staged_overflow() {
    let result = layout::Staged::try_from(usize::MAX);
    assert!(
        result.is_err(),
        "an oversized staged count must be rejected"
    );
    let error = result.err().expect("oversized staged count");
    assert!(matches!(
        error,
        layout::Error::Staged { actual: usize::MAX, maximum }
            if maximum == u32::MAX as usize - 1
    ));
}

#[test]
fn rejects_warm_over_cap() {
    use dope::core::driver::route::KeyTag;
    use dope::net::Resource;
    use o3::buffer::pool::GrowingError;

    let warm = NonZero::<u32>::MIN.saturating_add(2);
    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let slots = endpoint::Sessions::try_new(1).expect("session storage");
    let result = Bootstrap::<Server>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(Arc::new(config))
            .with_growth(warm)
            .bind(&slots),
    );
    assert!(matches!(
        result,
        Err(Resource::Pool(GrowingError::Warm {
            requested: actual,
            maximum: 2,
        })) if actual == warm
    ));
}
