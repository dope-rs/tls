use std::{collections::VecDeque, convert::Infallible, ops::ControlFlow};

use dope::{
    core::{
        driver::{life, retained},
        io::event::{self, net::recv},
    },
    net::link::{
        event::{ControlRecv, DispatchRecv, Reservation},
        slot::transmit::outcome::Retention,
    },
};

use crate::common::{
    Read,
    retry::{Error, Held, Key, Mode, Pool, native::next, pending, settle, submit},
};

/// Retains real receive completions until the handshake send completion is held,
/// then processes authenticated input before settling that original send owner.
pub(super) fn establish<'p, 'w, 'd: 'w>(
    pool: &mut Pool<'p, 'w, 'd>,
    keys: [Key<'d>; 2],
    scope: &mut life::Scope<'_, 'd>,
    mode: Mode,
) -> Result<Option<Held>, Error> {
    {
        let mut context = scope.context();
        let owner = retained::raw::Owner::from_driver(context.driver_ref());
        let mut driver = retained::Context::new(context.reborrow(), owner);
        for key in keys
            .into_iter()
            .take(if matches!(mode, Mode::Held) { 1 } else { 2 })
        {
            pool.recv()
                .arm(key, &mut driver)
                .map_err(|failure| Error::Submit(failure.cause))?;
        }
    }
    let mut ready = [false; 2];
    let mut queued = VecDeque::new();
    let mut held = None;
    let mut observed = None;
    loop {
        let event = if held.is_some() || observed.is_some() {
            match queued.pop_front() {
                Some(done) => event::Kind::Recv(done),
                None => next(scope)?.into_kind(),
            }
        } else {
            next(scope)?.into_kind()
        };
        match event {
            event::Kind::Recv(done) => {
                if matches!(mode, Mode::Held)
                    && held.is_none()
                    && observed.is_none()
                    && pool
                        .inspect()
                        .get(keys[0])
                        .is_some_and(|conn| conn.send_status().is_inflight())
                {
                    queued.push_back(done);
                    continue;
                }
                let done =
                    match done.dispatch(|_, _, value| ControlFlow::<_, Infallible>::Break(value)) {
                        ControlFlow::Break(done) => done,
                        ControlFlow::Continue(never) => match never {},
                    };
                let bytes = match done.classify() {
                    recv::Kind::Data(bytes) => bytes,
                    recv::Kind::Control(_) => return Err(Error::RecvEvent),
                };
                let data = match pool.reserve().data(bytes) {
                    Reservation::Ready(data) => data.scoped(),
                    Reservation::Control(control) => DispatchRecv::Control(control),
                    _ => return Err(Error::Reserve),
                };
                let key = match data {
                    DispatchRecv::Chunk(key, mut chunk) => {
                        let index = keys
                            .iter()
                            .position(|other| *other == key)
                            .ok_or(Error::Key)?;
                        let mut marker = Vec::new();
                        chunk
                            .drive(
                                Ok(()),
                                &mut Read(|bytes: &[u8]| {
                                    marker.extend_from_slice(bytes);
                                    bytes.len()
                                }),
                            )
                            .map_err(Error::Consume)?;
                        if marker.as_slice() != [b'A' + index as u8] {
                            return Err(Error::Record);
                        }
                        ready[index] = true;
                        key
                    }
                    DispatchRecv::Control(ControlRecv::NoChunk(key)) => key,
                    DispatchRecv::Control(ControlRecv::Failed { error, .. }) => {
                        return Err(Error::Receive(error));
                    }
                    DispatchRecv::Control(ControlRecv::Credit { cause, .. }) => {
                        return Err(Error::Credit(cause));
                    }
                    _ => return Err(Error::Control),
                };
                submit(pool, key, scope)?;
            }
            event::Kind::Send(done) => {
                if matches!(mode, Mode::Held) && observed.is_none() {
                    if held.is_some() {
                        return Err(Error::Flight);
                    }
                    held = Some(done);
                } else {
                    settle(pool, done, scope)?;
                }
            }
            _ => return Err(Error::Handshake),
        }
        pending(pool, scope, |_| {})?;
        scope.with_driver(|mut context, mut control| {
            let turn = control.begin();
            let owner = retained::raw::Owner::from_driver(context.driver_ref());
            let mut driver = retained::Context::new(context.reborrow(), owner);
            pool.recv()
                .flush(turn.turn().maint(), &mut driver)
                .map_err(|failure| Error::Submit(failure.cause))
        })?;
        if matches!(mode, Mode::Held) && observed.is_none() && ready[0] {
            let conn = pool.inspect().get(keys[0]).ok_or(Error::Key)?;
            let status = conn.send_status();
            observed = Some(Held {
                inflight: status.is_inflight(),
                retained: matches!(status.retention(), Retention::Held),
                rearm: pool.inspect().has_rearm(),
            });
            settle(pool, held.take().ok_or(Error::Flight)?, scope)?;
            let mut context = scope.context();
            let owner = retained::raw::Owner::from_driver(context.driver_ref());
            let mut driver = retained::Context::new(context.reborrow(), owner);
            pool.recv()
                .arm(keys[1], &mut driver)
                .map_err(|failure| Error::Submit(failure.cause))?;
        }
        if ready == [true; 2]
            && keys.into_iter().all(|key| {
                pool.get_mut(key)
                    .is_some_and(|conn| !conn.send_status().is_inflight())
            })
        {
            return Ok(observed);
        }
    }
}
