use std::{
    convert::Infallible,
    io::{self, Read as _},
    net::SocketAddr,
    num::NonZero,
};

use dope::{
    core::{
        Errno,
        driver::{
            life::{self, recovery},
            receive::credit::error::Arm,
            result::{self, poll, poll::fault},
            retained::{self, flight},
            route::{Epoch, KeyTag, indices::SlotIndex, kind, lease, table::conn},
            settings,
        },
        io::{
            event::{
                self,
                batch::Flow,
                net::{accept, send},
            },
            socket::{self, option, pending::Cause},
        },
    },
    net::{
        self, Listen,
        link::{
            egress::{self, reserve::demand},
            event::{SendFailure, SendOutcome},
            pool::{
                self,
                change::{self, accept::Outcome},
                pending,
                recv::input,
            },
            slot::transmit,
        },
        tcp::{self, Tcp},
        wire::domain,
    },
};
use dope_test::{
    harness::peer,
    scope::{self, Driver},
};
use dope_tls::tls::{Tls, roles::Server};
use o3::{alloc, buffer::write::consume};

use crate::common::{
    fiber::{Connect, Peer},
    state,
};

mod hello;
pub mod native;
use hello::establish;
use native::{commit, next};

type Route = KeyTag<0>;
type Wire = Tls<Server>;
type Key<'d> = pool::Key<'d, Route>;
type Pool<'p, 'w, 'd> = pool::Pool<'p, 'w, 'd, Route, Tcp, Wire, (), input::Scoped, &'d [u8]>;

#[derive(Clone, Copy)]
pub enum Mode {
    Reply,
    Close,
    Held,
}

#[derive(Debug)]
pub struct Held {
    pub inflight: bool,
    pub retained: bool,
    pub rearm: bool,
}

#[derive(Debug)]
pub enum Error {
    Config(dope_tls::Error),
    Open(dope_tls::Error),
    Resource(net::Resource),
    Bind(net::BindingError),
    Allocation(alloc::Error),
    Route(lease::Error),
    Submit(result::SubmitError),
    Rejected(SendFailure<result::SubmitError>),
    Send(SendFailure<Errno>),
    Invalid(transmit::Invalid),
    Accept(accept::Failure),
    Tuning(Cause),
    Dispatch(fault::Dispatch),
    Commit(poll::Error),
    Wait(poll::Error),
    Spawn(peer::Spawn),
    Peer(peer::Finish),
    Connect(Connect),
    Consume(consume::Error),
    Receive(Errno),
    Credit(Arm),
    AcceptEvent,
    Flight,
    Opened,
    Peers,
    CommitLimit,
    RecvEvent,
    Reserve,
    Key,
    Record,
    Control,
    Handshake,
    Sender,
    Settlement,
    Busy,
    PendingSender,
    SendEvent,
    Deadline,
    Timeout,
}

pub fn run(
    mode: Mode,
    test: impl for<'p, 'w, 'd> FnOnce(
        &mut Pool<'p, 'w, 'd>,
        [Key<'d>; 2],
        &mut life::Scope<'_, 'd>,
        Option<Held>,
    ) -> Result<(), Error>,
    policy: impl recovery::Observe,
    finish: impl for<'owner> FnOnce(
        Result<Result<[Vec<u8>; 2], Error>, scope::Error<'owner, Result<[Vec<u8>; 2], Error>>>,
    ),
) -> Result<(), Error> {
    let (end, pubkey) = Peer::try_server().map_err(Error::Config)?;
    let storage = domain::Owner::<Wire, Route>::try_new(conn::Capacity::fixed::<2>())
        .map_err(Error::Resource)?;
    let config = settings::Config::default()
        .with_queues(state::QUEUES)
        .with_files(settings::FileSlots::fixed::<3, 2>())
        .with_receive(settings::Receive::fixed::<8, 4096>());
    Driver::new(config).with_scope(
        |scope| {
            let send =
                NonZero::<usize>::MIN.saturating_add(usize::from(matches!(mode, Mode::Held)));
            let Ok(end) = storage.bind(end.with_send(send));
            prepare(scope, end, pubkey, mode, test)
        },
        policy,
        finish,
    );
    Ok(())
}

fn prepare<'w, 'd: 'w>(
    scope: &mut life::Scope<'_, 'd>,
    end: domain::Endpoint<'w, Wire, Route>,
    pubkey: [u8; 32],
    mode: Mode,
    test: impl for<'p> FnOnce(
        &mut Pool<'p, 'w, 'd>,
        [Key<'d>; 2],
        &mut life::Scope<'_, 'd>,
        Option<Held>,
    ) -> Result<(), Error>,
) -> Result<[Vec<u8>; 2], Error> {
    change::try_prepare::<Route, Tcp, Wire, (), input::Scoped, &'d [u8], 32, _, _, _, _>(
        domain::Retained::ZERO,
        domain::Resident::ZERO,
        demand::Fallible::prepare(egress::Config::DEFAULT, conn::Capacity::fixed::<2>()),
        end,
        scope,
        life::Scope::context,
        |(prepared, need), scope| {
            let (mut pool, setup) = {
                let mut driver = scope.context();
                let flights = driver
                    .storage
                    .reborrow()
                    .try_flights(need)
                    .map_err(Error::Allocation)?
                    .slots();
                let route = driver
                    .storage
                    .reborrow()
                    .try_reserve::<Route>()
                    .map_err(Error::Route)?;
                // SAFETY: submitted storage and flights remain alive through native
                // quiescence and pool.finish, including every early test failure.
                let pool = unsafe { prepared.commit(flights).bind(route) };
                let setup = (|| {
                    let (listener, address) = Tcp::bind(
                        &mut driver,
                        &SocketAddr::from(([127, 0, 0, 1], 0)),
                        socket::Backlog::fixed::<2>(),
                        &tcp::Config::default(),
                    )
                    .map_err(Error::Bind)?;
                    let slots = driver
                        .storage
                        .reborrow()
                        .try_flights(flight::Need::<KeyTag<1>>::new(
                            flight::Capacity::fixed::<1>(),
                        ))
                        .map_err(Error::Allocation)?
                        .slots();
                    let target = driver
                        .driver_ref()
                        .targets::<KeyTag<1>>()
                        .bind(SlotIndex::ZERO, Epoch::INITIAL);
                    let accept = slots
                        .accept(
                            driver.reborrow(),
                            &listener,
                            target.operation::<kind::Accept>(),
                        )
                        .map_err(Error::Submit)?;
                    Ok::<_, Error>((listener, address, slots, target, Some(accept)))
                })();
                (pool, setup)
            };
            let (listener, address, slots, target, mut flight) = match setup {
                Ok(setup) => setup,
                Err(cause) => {
                    scope.finish(true, |_, finish| pool.finish(finish, |_, _| {}));
                    return Err(cause);
                }
            };
            let result = peer::Peer::at(address)
                .with_many::<2, _, _>(
                    move |[first, second]| {
                        let mut first = Peer::establish(first, pubkey)?;
                        first.try_send(b"A")?;
                        let mut second = Peer::establish(second, pubkey)?;
                        second.try_send(b"B")?;
                        let first = first.try_recv()?;
                        let second = match mode {
                            Mode::Reply | Mode::Held => second.try_recv()?,
                            Mode::Close => receive_close(&mut second)?,
                        };
                        Ok::<_, Connect>([first, second])
                    },
                    |peers| {
                        let result = (|| {
                            let mut keys = [None; 2];
                            for (index, key) in keys.iter_mut().enumerate() {
                                let done = match next(scope)?.into_kind() {
                                    event::Kind::Accept(done) => done,
                                    _ => return Err(Error::AcceptEvent),
                                };
                                let (_, flow, result) = done.into_parts();
                                if flow == Flow::Last {
                                    drop(flight.take().ok_or(Error::Flight)?);
                                }
                                let fd = match result {
                                    accept::Outcome::Accepted(fd) => fd.bind(),
                                    accept::Outcome::Failed(cause) => {
                                        return Err(Error::Accept(cause));
                                    }
                                };
                                let ready = fd.ready_handle();
                                let opened = pool
                                    .accept_with(
                                        conn::Capacity::fixed::<2>(),
                                        fd,
                                        option::Set::EMPTY,
                                        |_| Ok::<_, Infallible>(()),
                                        &mut scope.context(),
                                    )
                                    .map_err(|cause| Error::Open(cause.into_cause()))?;
                                let opened = match opened {
                                    Outcome::Ready(key) => key,
                                    Outcome::Failed(_, cause) => {
                                        return Err(Error::Tuning(cause));
                                    }
                                    Outcome::Rejected(never) => match never {},
                                    _ => return Err(Error::Opened),
                                };
                                ready.set_target(opened.target().dispatch());
                                *key = Some(opened);
                                if index == 0 && flight.is_none() {
                                    flight = Some(
                                        slots
                                            .accept(
                                                scope.context(),
                                                &listener,
                                                target.operation::<kind::Accept>(),
                                            )
                                            .map_err(Error::Submit)?,
                                    );
                                }
                            }
                            let keys = match keys {
                                [Some(first), Some(second)] => [first, second],
                                _ => return Err(Error::Peers),
                            };
                            let held = establish(&mut pool, keys, scope, mode)?;
                            test(&mut pool, keys, scope, held)
                        })();
                        let sent = commit(scope);
                        let received = peers.finish().map_err(Error::Peer);
                        result?;
                        sent?;
                        received?.map_err(Error::Connect)
                    },
                )
                .map_err(Error::Spawn);
            listener.close(&mut scope.context());
            scope.finish(true, |_, finish| pool.finish(finish, |_, _| {}));
            drop(flight);
            result?
        },
    )
    .map_err(Error::Resource)?
}

/// Requires authenticated TLS EOF before observing the native write shutdown.
fn receive_close(peer: &mut Peer<'_>) -> Result<Vec<u8>, Connect> {
    match peer.try_recv() {
        Err(Connect::Closed) => {}
        Err(cause) => return Err(cause),
        Ok(_) => return Err(Connect::Io(io::ErrorKind::InvalidData.into())),
    }
    let mut byte = [0];
    if peer.tls.reader().read(&mut byte).map_err(Connect::Io)? != 0 {
        return Err(Connect::Io(io::ErrorKind::InvalidData.into()));
    }
    if peer.socket.read(&mut byte).map_err(Connect::Io)? != 0 {
        return Err(Connect::Io(io::ErrorKind::InvalidData.into()));
    }
    Ok(Vec::new())
}

pub fn submit<'p, 'w, 'd: 'w>(
    pool: &mut Pool<'p, 'w, 'd>,
    key: Key<'d>,
    scope: &mut life::Scope<'_, 'd>,
) -> Result<(), Error> {
    let mut context = scope.context();
    let owner = retained::raw::Owner::from_driver(context.driver_ref());
    let mut driver = retained::Context::new(context.reborrow(), owner);
    let mut sender = pool.sender(key).ok_or(Error::Sender)?;
    submission(sender.submit(&mut driver))
}

fn submission(attempt: transmit::Attempt) -> Result<(), Error> {
    match attempt {
        transmit::Attempt::Runnable(_)
        | transmit::Attempt::Waiting
        | transmit::Attempt::Quiescent(_) => Ok(()),
        transmit::Attempt::Rejected(cause, _) => Err(Error::Rejected(cause)),
        transmit::Attempt::Invalid(cause) => Err(Error::Invalid(cause)),
    }
}

pub fn settle<'p, 'w, 'd: 'w>(
    pool: &mut Pool<'p, 'w, 'd>,
    done: send::Completion<'d>,
    scope: &mut life::Scope<'_, 'd>,
) -> Result<Key<'d>, Error> {
    let mut context = scope.context();
    let owner = retained::raw::Owner::from_driver(context.driver_ref());
    let mut driver = retained::Context::new(context.reborrow(), owner);
    match pool.settle(done).settle_owned(&mut driver, |_, _| {}) {
        SendOutcome::Queued { key, .. } | SendOutcome::Terminal { key } => Ok(key),
        SendOutcome::Rejected { failure, .. } => Err(Error::Rejected(failure)),
        SendOutcome::Failed { failure, .. } => Err(Error::Send(failure)),
        SendOutcome::Invalid { error, .. } => Err(Error::Invalid(error)),
        _ => Err(Error::Settlement),
    }
}

pub fn pending<'p, 'w, 'd: 'w>(
    pool: &mut Pool<'p, 'w, 'd>,
    scope: &mut life::Scope<'_, 'd>,
    mut observe: impl FnMut(Key<'d>),
) -> Result<(), Error> {
    let round = pending::Pending::of(pool)
        .try_round()
        .map_err(|_| Error::Busy)?;
    scope.with_driver(|mut context, mut control| {
        let turn = control.begin();
        let owner = retained::raw::Owner::from_driver(context.driver_ref());
        let mut driver = retained::Context::new(context.reborrow(), owner);
        let mut result = Ok(());
        round.run(turn.turn().maint(), |key| {
            observe(key);
            let attempt = pool
                .sender(key)
                .ok_or(Error::PendingSender)
                .and_then(|mut sender| submission(sender.submit(&mut driver)));
            if result.is_ok() {
                result = attempt;
            }
            pending::Disposition::Idle
        });
        result
    })
}
