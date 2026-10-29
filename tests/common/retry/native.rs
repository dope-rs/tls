use std::{
    ops::ControlFlow,
    time::{Duration, Instant},
};

use dope::core::{
    driver::{life, result::poll},
    io::{
        Event,
        event::{self, net::send},
    },
};

use crate::common::retry::Error;

pub(super) fn commit(scope: &mut life::Scope<'_, '_>) -> Result<(), Error> {
    for _ in 0..64 {
        let state = scope.with_driver(|mut driver, mut control| {
            let mut turn = control.begin();
            driver.commit(turn.reactor()).map_err(Error::Commit)
        })?;
        match state {
            poll::Commit::Drained => return Ok(()),
            poll::Commit::Pending => {}
        }
    }
    Err(Error::CommitLimit)
}

pub fn next_send<'d>(scope: &mut life::Scope<'_, 'd>) -> Result<send::Completion<'d>, Error> {
    match next(scope)?.into_kind() {
        event::Kind::Send(done) => Ok(done),
        _ => Err(Error::SendEvent),
    }
}

pub(super) fn next<'d>(scope: &mut life::Scope<'_, 'd>) -> Result<Event<'d>, Error> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or(Error::Deadline)?;
    loop {
        let event = scope.with_driver(|mut driver, mut control| {
            let mut turn = control.begin();
            match driver.dispatch(turn.reactor(), |event, _| ControlFlow::Break(event)) {
                poll::Dispatch::Ready {
                    retained: Some(event),
                    ..
                } => return Ok(Some(event)),
                poll::Dispatch::Ready { retained: None, .. } => {}
                poll::Dispatch::Fault(cause) => return Err(Error::Dispatch(cause)),
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Timeout)?;
            driver
                .wait(turn.reactor(), Some(left))
                .map_err(Error::Wait)?;
            Ok(None)
        })?;
        if let Some(event) = event {
            return Ok(event);
        }
    }
}
