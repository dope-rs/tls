use std::{marker, mem};

use dope::net::wire::send;
use o3::buffer::{self, pool};
use shin::client::config;

use crate::{clock, error, staging, state, transmissions};

mod connection;
mod egress;
pub mod endpoints;
mod open;
#[doc(hidden)]
pub mod receive;
pub mod roles;
mod wire;

/// Validated client endpoint plan consumed to bind one reusable,
/// allocation-free connection pool. Its first connection consumes configured
/// resumption state.
pub struct ClientPlan {
    prepared: config::Prepared,
    identity: Option<config::IdentityTemplate>,
    clock: clock::Clock,
}

pub(crate) struct Dial {
    pub(crate) prepared: config::Prepared,
    pub(crate) identity: Option<config::IdentityTemplate>,
    pub(crate) clock: clock::Clock,
}

impl ClientPlan {
    /// Validates and prepares a reusable client configuration.
    pub fn new(config: config::Config) -> Result<Self, error::Error> {
        let prepared = config
            .try_into_prepared()
            .map_err(error::Error::InvalidConfig)?;
        Ok(Self {
            prepared,
            identity: None,
            clock: clock::Clock::System,
        })
    }

    /// Validates and prepares a reusable mutually authenticated client.
    pub fn mutual(
        config: config::Config,
        identity: config::Identity,
    ) -> Result<Self, error::Error> {
        let mut plan = Self::new(config)?;
        plan.identity = Some(
            identity
                .try_into_template()
                .map_err(error::Error::InvalidConfig)?,
        );
        Ok(plan)
    }

    /// Uses `clock` for every connection opened from this plan.
    pub fn with_clock(mut self, clock: clock::Clock) -> Self {
        self.clock = clock;
        self
    }

    pub(crate) fn into_dial(self) -> Dial {
        Dial {
            prepared: self.prepared,
            identity: self.identity,
            clock: self.clock,
        }
    }
}

pub struct Tls<R: roles::Protocol = roles::Server>(marker::PhantomData<fn() -> R>);

#[doc(hidden)]
pub struct Connection<'d, R: roles::Protocol = roles::Server, const ID: u8 = 0> {
    state: connection::ConnectionState<'d, R::Session<'d, ID>>,
    send_inflight: bool,
}

impl<'d, R: roles::Protocol, const ID: u8> Connection<'d, R, ID> {
    fn into_state(mut self, mut send: SendState<'d>) -> state::State<'d, R::Session<'d, ID>> {
        state::Internals::swap_pending_buffer(&mut self.state.tls, &mut send.buffer);
        self.state.tls
    }
}

pub struct SendState<'d> {
    buffer: Option<pool::BorrowedCursor<'d>>,
}

impl<'d> SendState<'d> {
    fn new() -> Self {
        Self { buffer: None }
    }

    fn reserve(&mut self, pool: &'d buffer::Pool) -> bool {
        if self.buffer.is_none() {
            self.buffer = pool.try_acquire_borrowed_buffer();
        }
        self.buffer.is_some()
    }
}

impl send::StorageBackend for SendState<'_> {
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_ref().map_or(&[], |cursor| cursor.as_slice())
    }

    fn release(self) -> send::Availability {
        if self.buffer.is_some() {
            send::Availability::Released
        } else {
            send::Availability::Unchanged
        }
    }
}

impl<'d> transmissions::SendBuffer for SendState<'d> {
    type Cursor = pool::BorrowedCursor<'d>;

    fn buffer_mut(&mut self) -> Option<&mut Self::Cursor> {
        self.buffer.as_mut()
    }

    fn release_if_empty(&mut self) -> send::Availability {
        let released = self.buffer.as_ref().is_some_and(|cursor| cursor.is_empty());
        if released {
            self.buffer = None;
            send::Availability::Released
        } else {
            send::Availability::Unchanged
        }
    }
}

impl<'d, R: roles::Protocol, const ID: u8> transmissions::SendProtocol for Connection<'d, R, ID> {
    type Storage = SendState<'d>;

    fn try_buffer<'a>(
        &self,
        storage: &'a mut Self::Storage,
    ) -> Option<&'a mut <Self::Storage as transmissions::SendBuffer>::Cursor> {
        let pool = state::Internals::pending_pool(&self.state.tls);
        storage.reserve(pool).then_some(())?;
        storage.buffer.as_mut()
    }

    fn needs_buffer(&self) -> bool {
        !self.send_inflight && state::Internals::has_pending_control(&self.state.tls)
    }

    fn encrypt(&mut self, egress: &mut pool::BorrowedCursor<'d>, plain: &[u8]) -> usize {
        if plain.is_empty() {
            return 0;
        }
        egress::Egress::new(self).encrypt(egress, plain)
    }

    fn encrypt_vectored(
        &mut self,
        egress: &mut pool::BorrowedCursor<'d>,
        vectored: &send::Vectored<'_>,
    ) -> usize {
        if vectored.bytes() == 0 {
            return 0;
        }
        egress::Egress::new(self).encrypt_vectored(egress, vectored)
    }

    fn propagate_close(&mut self, _egress: &mut pool::BorrowedCursor<'d>) -> bool {
        egress::Egress::new(self).propagate_close()
    }

    fn drain_to_egress(&mut self, egress: &mut pool::BorrowedCursor<'d>) {
        if self.send_inflight {
            return;
        }
        if state::Internals::drain_pending_control_into(&mut self.state.tls, egress).is_err() {
            self.state.close = true;
        }
    }

    fn send_inflight(&mut self) -> &mut bool {
        &mut self.send_inflight
    }
}

const _: () = assert!(mem::size_of::<Connection<'static>>() < staging::MAX_TLS_RECORD);
const _: () = assert!(mem::size_of::<roles::Server>() == 0);
const _: () = assert!(mem::size_of::<roles::Client>() == 0);
const _: () = assert!(
    mem::size_of::<Connection<'static, roles::Client>>()
        == mem::size_of::<Connection<'static, roles::Server>>()
);
