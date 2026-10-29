use std::convert::Infallible;

use dope::{
    core::{
        driver::{
            life::recovery,
            result::SubmitCause,
            retained::{self, flight},
            route::{Epoch, KeyTag, indices::SlotIndex},
        },
        io::{
            fd::handles::Descriptor,
            socket::{self, install::Install},
        },
    },
    net::link::{egress, pool::pending::Pending, slot::transmit::Finalize},
};

use crate::common::retry::{self, Error, Mode, native};

pub mod common;

#[test]
fn inflight_receive() {
    retry::run(
        Mode::Held,
        |pool, keys, scope, held| {
            let held = held.expect("plaintext arrives before handshake send settlement");
            assert!(held.inflight, "receive preserves the submitted send");
            assert!(held.retained, "submitted ciphertext retains its owner");
            assert!(
                !held.rearm,
                "inflight receive must not leave a spinning waiter"
            );
            for key in keys {
                {
                    let mut driver = scope.context();
                    assert!(matches!(
                        pool.egress_mut(key)
                            .expect("established peer")
                            .queue
                            .try_enqueue(driver.region_token(), b"reply"),
                        egress::Enqueue::Committed,
                    ));
                }
                retry::submit(pool, key, scope)?;
                let done = native::next_send(scope)?;
                assert_eq!(retry::settle(pool, done, scope)?, key);
            }
            Ok::<_, Error>(())
        },
        recovery::Policy::new(
            |_| {},
            |failure: recovery::Recovery<'_, '_>| -> Infallible {
                panic!("native TLS fixture recovery: {:?}", failure.cause())
            },
        ),
        |result| {
            let replies = result
                .map_err(|cause| format!("{:?}", cause.cause()))
                .expect("TLS fixture scope")
                .expect("inflight handshake receive");
            assert_eq!(replies, [b"reply".to_vec(), b"reply".to_vec()]);
        },
    )
    .expect("TLS send fixture");
}

#[test]
fn released_output() {
    retry::run(
        Mode::Reply,
        |pool, [first, second], scope, _| {
            {
                let mut driver = scope.context();
                assert!(matches!(
                    pool.egress_mut(first)
                        .expect("first peer")
                        .queue
                        .try_enqueue(driver.region_token(), b"first reply"),
                    egress::Enqueue::Committed,
                ));
            }
            retry::submit(pool, first, scope)?;
            let held = native::next_send(scope)?;
            assert!(
                pool.get_mut(first)
                    .expect("first peer")
                    .send_status()
                    .is_inflight()
            );

            {
                let mut driver = scope.context();
                assert!(matches!(
                    pool.egress_mut(second)
                        .expect("second peer")
                        .queue
                        .try_enqueue(driver.region_token(), b"second reply"),
                    egress::Enqueue::Committed,
                ));
            }
            retry::submit(pool, second, scope)?;
            assert!(
                !pool
                    .egress_mut(second)
                    .expect("second peer")
                    .queue
                    .is_empty()
            );
            assert!(
                !pool
                    .get_mut(second)
                    .expect("second peer")
                    .send_status()
                    .is_inflight()
            );
            assert!(Pending::of(pool).is_empty(), "capacity wait must not spin");

            assert_eq!(retry::settle(pool, held, scope)?, first);
            let mut retried = Vec::new();
            retry::pending(pool, scope, |key| retried.push(key))?;
            assert_eq!(retried, [second]);
            assert!(
                pool.egress_mut(second)
                    .expect("second peer")
                    .queue
                    .is_empty()
            );
            assert!(
                pool.get_mut(second)
                    .expect("second peer")
                    .send_status()
                    .is_inflight()
            );
            Ok::<_, Error>(())
        },
        recovery::Policy::new(
            |_| {},
            |failure: recovery::Recovery<'_, '_>| -> Infallible {
                panic!("native TLS fixture recovery: {:?}", failure.cause())
            },
        ),
        |result| {
            let result = result
                .map_err(|cause| format!("{:?}", cause.cause()))
                .expect("TLS fixture scope")
                .expect("TLS send retry");
            assert_eq!(result, [b"first reply".to_vec(), b"second reply".to_vec()]);
        },
    )
    .expect("TLS send fixture");
}

#[test]
fn pending_close() {
    retry::run(
        Mode::Close,
        |pool, [first, second], scope, _| {
            {
                let mut driver = scope.context();
                assert!(matches!(
                    pool.egress_mut(first)
                        .expect("first peer")
                        .queue
                        .try_enqueue(driver.region_token(), b"first reply"),
                    egress::Enqueue::Committed,
                ));
            }
            retry::submit(pool, first, scope)?;
            let held = native::next_send(scope)?;

            for _ in 0..2 {
                pool.get_mut(second).expect("second peer").shutdown();
                retry::submit(pool, second, scope)?;
                let conn = pool.get_mut(second).expect("second peer");
                assert!(conn.send_status().is_closing());
                assert!(conn.send_status().is_waiting());
                assert!(
                    !conn.send_status().is_inflight(),
                    "native write shutdown must wait for close_notify capacity",
                );
                assert!(Pending::of(pool).is_empty(), "capacity wait must not spin");
            }

            assert_eq!(retry::settle(pool, held, scope)?, first);
            let mut retried = Vec::new();
            retry::pending(pool, scope, |key| retried.push(key))?;
            assert_eq!(retried, [second]);
            assert!(
                pool.get_mut(second)
                    .expect("second peer")
                    .send_status()
                    .is_inflight()
            );

            let close = native::next_send(scope)?;
            assert!(matches!(close.outcome(), Ok(bytes) if !bytes.is_zero()));
            assert_eq!(retry::settle(pool, close, scope)?, second);
            retry::submit(pool, second, scope)?;
            assert!(
                pool.get_mut(second)
                    .expect("second peer")
                    .send_status()
                    .is_inflight()
            );
            Ok::<_, Error>(())
        },
        recovery::Policy::new(
            |_| {},
            |failure: recovery::Recovery<'_, '_>| -> Infallible {
                panic!("native TLS fixture recovery: {:?}", failure.cause())
            },
        ),
        |result| {
            let result = result
                .map_err(|cause| format!("{:?}", cause.cause()))
                .expect("TLS fixture scope")
                .expect("authenticated close before TCP EOF");
            assert_eq!(result, [b"first reply".to_vec(), Vec::new()]);
        },
    )
    .expect("TLS send fixture");
}

#[test]
fn seal_retries_native_full() {
    retry::run(
        Mode::Close,
        |pool, [first, second], scope, _| {
            {
                let mut context = scope.context();
                assert!(matches!(
                    pool.egress_mut(first)
                        .expect("first peer")
                        .queue
                        .try_enqueue(context.region_token(), b"first reply"),
                    egress::Enqueue::Committed,
                ));
            }
            retry::submit(pool, first, scope)?;
            let sent = native::next_send(scope)?;
            assert_eq!(retry::settle(pool, sent, scope)?, first);

            let socket;
            let flights;
            let admitted = {
                let mut context = scope.context();
                socket = Install::bind_udp(
                    context.reborrow(),
                    ([127, 0, 0, 1], 0).into(),
                    socket::Config::for_datagram(None),
                )
                .expect("queue pressure socket").0;
                flights = context
                    .storage
                    .reborrow()
                    .try_flights(flight::Need::<KeyTag<2>>::new(
                        flight::Capacity::fixed::<514>(),
                    ))
                    .expect("more flights than native queue capacity")
                    .slots();
                let target = context
                    .driver_ref()
                    .targets::<KeyTag<2>>()
                    .bind(SlotIndex::ZERO, Epoch::INITIAL);
                let mut admitted = 0;
                for _ in 0..513 {
                    match flights.shutdown(context.reborrow(), &socket, target) {
                        Ok(flight) => {
                            drop(flight);
                            admitted += 1;
                        }
                        Err(error) => {
                            assert_eq!(error.cause(), SubmitCause::Full);
                            break;
                        }
                    }
                }
                assert!(admitted < 513, "native queue fills before flight storage");
                let owner = retained::raw::Owner::from_driver(context.driver_ref());
                let mut driver = retained::Context::new(context.reborrow(), owner);
                for _ in 0..2 {
                    let egress = pool.egress_mut(second).expect("second peer");
                    let result = egress
                        .connection
                        .sending()
                        .seal(egress.flights, &mut driver);
                    assert!(matches!(
                        result,
                        Finalize::Rejected(failure) if failure.into_error().cause() == SubmitCause::Full
                    ));
                    assert!(!egress.connection.is_discarded());
                    assert!(!egress.connection.send_status().is_inflight());
                }
                admitted
            };
            for _ in 0..admitted {
                native::next_send(scope)?;
            }
            Descriptor::from(socket).close(&mut scope.context());

            {
                let mut context = scope.context();
                let owner = retained::raw::Owner::from_driver(context.driver_ref());
                let mut driver = retained::Context::new(context.reborrow(), owner);
                let egress = pool.egress_mut(second).expect("second peer");
                let wait = match egress
                    .connection
                    .sending()
                    .seal(egress.flights, &mut driver)
                {
                    Finalize::Armed(wait) => Some(wait),
                    Finalize::Settled | Finalize::Abandoned | Finalize::Rejected(_) => None,
                };
                wait.expect("retained close_notify must submit after native pressure")
                    .reschedule();
            }
            let close = native::next_send(scope)?;
            assert!(matches!(close.outcome(), Ok(bytes) if !bytes.is_zero()));
            assert_eq!(retry::settle(pool, close, scope)?, second);
            pool.get_mut(second).expect("second peer").shutdown();
            retry::submit(pool, second, scope)?;
            Ok::<_, Error>(())
        },
        recovery::Policy::new(
            |_| {},
            |failure: recovery::Recovery<'_, '_>| -> Infallible {
                panic!("native TLS fixture recovery: {:?}", failure.cause())
            },
        ),
        |result| {
            let result = result
                .map_err(|cause| format!("{:?}", cause.cause()))
                .expect("TLS fixture scope")
                .expect("authenticated close after native pressure");
            assert_eq!(result, [b"first reply".to_vec(), Vec::new()]);
        },
    )
    .expect("TLS send fixture");
}
