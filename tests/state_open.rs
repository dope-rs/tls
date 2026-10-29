use std::{convert::Infallible, num::NonZero, sync::Arc};

use dope::core::{
    driver::{
        life::recovery,
        receive::credit::{self, Take, Wake},
        route::{Epoch, KeyTag, indices::SlotIndex, table::conn::Capacity},
        settings,
    },
    io::transfer::Len,
};
use dope::net::wire::{
    domain::{Bootstrap as _, Limits},
    open::{self, Runtime as _},
    receive::reserve::{Completion as _, Outcome, Registration as _, Try as _, Wait},
    send::{Availability, Consume as _, Store as _},
};
use dope_test::scope::Driver;
use dope_tls::{
    config::raw::Identity,
    tls::{
        Tls,
        endpoint::{self, layout::Staged},
        protocol::Bootstrap,
        receive::policy::Policy,
        roles,
    },
};

#[test]
fn reuses_hello() {
    let slots = endpoint::Sessions::<roles::Client>::try_new(1).expect("session storage");
    let config = endpoint::Config::client(
        Arc::new(Identity::client([9; 32]).expect("client policy")),
        "example.com".try_into().expect("server name"),
    );
    let mut run = Bootstrap::<roles::Client>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        config.bind(&slots),
    )
    .expect("endpoint runtime");

    let hello = match run.open((), |(), wire, send| {
        open::Disposition::retry(send.as_slice().to_vec(), wire, send)
    }) {
        open::Outcome::Opened(hello) => Some(hello),
        _ => None,
    }
    .expect("initial client open");
    assert!(!hello.is_empty());
    assert!(matches!(
        run.open((), |(), wire, send| {
            assert_eq!(send.as_slice(), hello);
            open::Disposition::retry((), wire, send)
        }),
        open::Outcome::Opened(())
    ));
    let (mut wire, mut send) =
        match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
            open::Outcome::Opened(parts) => Some(parts),
            _ => None,
        }
        .expect("reuse admitted connection");
    let txn =
        match Policy::<roles::Client>::try_reserve::<KeyTag<0>>(&mut wire, &mut send, &mut run) {
            Outcome::Ready(txn) => Some(txn),
            _ => None,
        }
        .expect("reuse queued client hello");
    drop(txn);
    assert_eq!(send.as_slice(), hello);
    assert!(matches!(
        run.open(7, |_, _, _| open::Disposition::Commit(())),
        open::Outcome::Unavailable(7)
    ));
    drop((wire, send));
    assert!(matches!(
        run.open((), |(), wire, send| open::Disposition::Commit((wire, send))),
        open::Outcome::Opened(_)
    ));
}

#[test]
fn loan_limits() {
    let slots = endpoint::Sessions::<roles::Client>::try_new(2).expect("session storage");
    let config = endpoint::Config::client(
        Arc::new(Identity::client([9; 32]).expect("client policy")),
        "example.com".try_into().expect("server name"),
    )
    .with_send(NonZero::<usize>::MIN);
    let mut run = Bootstrap::<roles::Client>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<2, 0, 0, { 64 * 1024 }>(),
        config.bind(&slots),
    )
    .expect("endpoint runtime");
    let (first, send) =
        match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
            open::Outcome::Opened(parts) => Some(parts),
            _ => None,
        }
        .expect("first client open");
    assert!(!send.as_slice().is_empty());
    assert!(matches!(
        run.open((), |(), _, _| open::Disposition::Commit(())),
        open::Outcome::Unavailable(())
    ));
    assert!(matches!(send.release(), Availability::Released));
    let second = match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
        open::Outcome::Opened(parts) => Some(parts),
        _ => None,
    }
    .expect("send pressure must return its session admission");
    assert!(!second.1.as_slice().is_empty());
    drop((first, second));
}

#[test]
fn server_slots() {
    let slots = endpoint::Sessions::try_new(2).expect("session storage");
    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let mut run = Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<2, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(Arc::new(config))
            .with_send(NonZero::<usize>::MIN)
            .bind(&slots),
    )
    .expect("endpoint runtime");
    let mut opened = Vec::new();
    for _ in 0..2 {
        let parts = match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
            open::Outcome::Opened(parts) => Some(parts),
            _ => None,
        }
        .expect("available server session");
        assert!(parts.1.as_slice().is_empty());
        opened.push(parts);
    }
    assert!(matches!(
        run.open((), |(), _, _| open::Disposition::Commit(())),
        open::Outcome::Unavailable(())
    ));
    drop(opened.pop().expect("occupied session"));
    assert!(matches!(
        run.open((), |(), wire, send| open::Disposition::Commit((wire, send))),
        open::Outcome::Opened(_)
    ));
}

#[test]
fn runtime_drop() {
    let slots = endpoint::Sessions::<roles::Client>::try_new(1).expect("session storage");
    let config = endpoint::Config::client(
        Arc::new(Identity::client([9; 32]).expect("client policy")),
        "example.com".try_into().expect("server name"),
    );
    let mut run = Bootstrap::<roles::Client>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
        config.bind(&slots),
    )
    .expect("endpoint runtime");
    let (wire, send) = match run.open((), |(), wire, send| open::Disposition::Commit((wire, send)))
    {
        open::Outcome::Opened(parts) => Some(parts),
        _ => None,
    }
    .expect("client connection");
    drop(run);
    assert!(!send.as_slice().is_empty());
    drop(wire);
    assert!(matches!(send.release(), Availability::Released));
}

#[test]
fn pool_return() {
    let slots = endpoint::Sessions::try_new(2).expect("session storage");
    let config = Identity::from_seed(&[3; 32])
        .expect("server identity")
        .server()
        .expect("server policy");
    let mut run = Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
        Limits::fixed::<2, 0, 0, { 64 * 1024 }>(),
        endpoint::Config::from(Arc::new(config))
            .with_staged(Staged::fixed::<0>())
            .with_send(NonZero::<usize>::MIN)
            .bind(&slots),
    )
    .expect("endpoint runtime");
    let mut opened = Vec::new();
    for _ in 0..2 {
        let parts = match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
            open::Outcome::Opened(parts) => Some(parts),
            _ => None,
        }
        .expect("server connection");
        opened.push(parts);
    }
    for complete in [true, false] {
        for (wire, send) in &mut opened {
            let txn = match Policy::<roles::Server>::try_reserve::<KeyTag<0>>(wire, send, &mut run)
            {
                Outcome::Ready(txn) => Some(txn),
                _ => None,
            }
            .expect("previous reservation must release both pool loans");
            if complete {
                txn.complete();
            } else {
                drop(txn);
            }
            assert!(send.as_slice().is_empty());
        }
    }
}

#[test]
fn cancelled_waiter() {
    let mut reports = Vec::new();
    Driver::new(settings::Config::default()).with_driver(
        |driver| {
            let site = driver.driver_ref();
            let slots = endpoint::Sessions::<roles::Client>::try_new(3).expect("session storage");
            let config = endpoint::Config::client(
                Arc::new(Identity::client([9; 32]).expect("client policy")),
                "example.com".try_into().expect("server name"),
            )
            .with_send(NonZero::<usize>::MIN);
            let mut run = Bootstrap::<roles::Client>::try_runtime::<KeyTag<0>>(
                Limits::fixed::<3, 0, 0, { 64 * 1024 }>(),
                config.bind(&slots),
            )
            .expect("endpoint runtime");
            let mut peers = [(); 2].map(|()| {
                let (mut wire, mut send) =
                    match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
                        open::Outcome::Opened(parts) => Some(parts),
                        _ => None,
                    }
                    .expect("handshaking client");
                send.consume_max(Len::MAX);
                let txn = match Policy::<roles::Client>::try_reserve::<KeyTag<0>>(
                    &mut wire, &mut send, &mut run,
                ) {
                    Outcome::Ready(txn) => Some(txn),
                    _ => None,
                }
                .expect("release consumed client hello");
                txn.complete();
                (wire, send)
            });
            let (_holder, send) =
                match run.open((), |(), wire, send| open::Disposition::Commit((wire, send))) {
                    open::Outcome::Opened(parts) => Some(parts),
                    _ => None,
                }
                .expect("hold the only ciphertext buffer");
            assert!(!send.as_slice().is_empty());

            let credits = site
                .scheduler()
                .try_storage(Capacity::fixed::<2>())
                .expect("receive credits");
            let indices = [SlotIndex::ZERO, SlotIndex::fixed::<1>()];
            let targets = indices.map(|slot| {
                site.targets::<KeyTag<0>>()
                    .bind(slot, Epoch::INITIAL)
                    .dispatch()
            });
            let ready = targets.map(|target| site.ready().make_slot(target).expect("ready slot"));
            for ((wire, send), ((slot, target), ready)) in peers
                .iter_mut()
                .zip(indices.into_iter().zip(targets).zip(&ready))
            {
                let blocked =
                    match Policy::<roles::Client>::try_reserve::<KeyTag<0>>(wire, send, &mut run) {
                        Outcome::Blocked(blocked) => Some(blocked),
                        _ => None,
                    }
                    .expect("both handshakes wait for the shared send buffer");
                let pending = credits
                    .get(slot)
                    .expect("credit slot")
                    .control()
                    .arm(target, ready.target())
                    .expect("idle credit");
                Wait::<KeyTag<0>, Tls<roles::Client>>::register(blocked, pending)
                    .expect("handshake waiter")
                    .commit();
            }

            assert!(!run.is_ready(), "occupied send capacity must not spin");
            assert!(matches!(send.release(), Availability::Released));
            Policy::<roles::Client>::release_send::<KeyTag<0>>(&mut run);
            assert!(matches!(
                credits.get(SlotIndex::ZERO).expect("first credit").take(),
                Take::Ready(Wake::Retry)
            ));
            Policy::<roles::Client>::cancel(&mut run, credit::Id::new(targets[0]));
            let [first, (mut wire, mut send)] = peers;
            drop(first);

            assert!(run.is_ready(), "unused send capacity must remain runnable");
            let next = run.take_ready().expect("second handshake must progress");
            assert!(next.id() == credit::Id::new(targets[1]));
            next.retry();
            assert!(matches!(
                credits
                    .get(SlotIndex::fixed::<1>())
                    .expect("second credit")
                    .take(),
                Take::Ready(Wake::Retry)
            ));
            let txn = match Policy::<roles::Client>::try_reserve::<KeyTag<0>>(
                &mut wire, &mut send, &mut run,
            ) {
                Outcome::Ready(txn) => Some(txn),
                _ => None,
            }
            .expect("second handshake acquires the released send buffer");
            txn.complete();
            assert!(!run.is_ready());
        },
        recovery::Policy::new(
            |event| reports.push(event),
            |failure: recovery::Recovery<'_, '_>| -> Infallible {
                panic!("native recovery: {:?}", failure.cause())
            },
        ),
        |result| {
            result
                .map_err(|cause| format!("{:?}", cause.cause()))
                .expect("driver lifecycle");
        },
    );
    assert!(
        reports.is_empty(),
        "unexpected native retirement: {reports:?}"
    );
}
