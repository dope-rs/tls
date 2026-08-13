use core::{marker, mem};
use std::{cell, io};

use o3::collections::slab;
use shin::client::{self, workspace};
use shin::connection;
use shin::wire::handshake;

use crate::clock;
use crate::state::sessions;
use crate::tls;

#[doc(hidden)]
pub struct Storage<const ID: u8 = 0> {
    capacity: slab::Capacity,
    initialized: cell::OnceCell<Initialized<ID>>,
}

pub(crate) struct Initialized<const ID: u8> {
    pool: workspace::Pool<clock::Clock>,
    clock: clock::Clock,
    _route: marker::PhantomData<fn() -> Route<ID>>,
}

struct Route<const ID: u8>;

impl<const ID: u8> Storage<ID> {
    pub(crate) fn new(capacity: slab::Capacity) -> Self {
        Self {
            capacity,
            initialized: cell::OnceCell::new(),
        }
    }

    pub(crate) fn bind(&self, plan: tls::ClientPlan) -> io::Result<&Initialized<ID>> {
        if self.initialized.get().is_some() {
            return Err(already_bound());
        }
        let tls::Dial {
            prepared,
            identity,
            clock,
        } = plan.into_dial();
        let initialized = Initialized {
            pool: prepared.into_pool(identity, self.capacity),
            clock,
            _route: marker::PhantomData,
        };
        self.initialized
            .set(initialized)
            .map_err(|_| already_bound())?;
        self.initialized.get().ok_or_else(already_bound)
    }
}

fn already_bound() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TLS client session storage is already bound",
    )
}

#[doc(hidden)]
pub struct Pooled<'d, const ID: u8 = 0>(
    client::PooledConnection<'d, clock::Clock>,
    marker::PhantomData<fn() -> Route<ID>>,
);

impl<const ID: u8> sessions::Peer for Pooled<'_, ID> {
    fn send_pending_key_update_response_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.0.key_updates().send_pending_into(events)
    }

    fn send_key_update_into<S: connection::EventSink + ?Sized>(
        &mut self,
        request: handshake::KeyUpdateRequest,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.0.key_updates().send_into(request, events)
    }

    fn note_application_data(&mut self) {
        self.0.key_updates().note_application_data();
    }

    fn selected_alpn(&self) -> Option<&[u8]> {
        self.0.selected_alpn()
    }
}

impl<const ID: u8> sessions::ClientPeer for Pooled<'_, ID> {
    fn start_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.0.start_into(events)
    }

    fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.0.read_into(epoch, data, events)
    }
}

impl<'d, const ID: u8> Pooled<'d, ID> {
    pub(crate) fn connect(initialized: &'d Initialized<ID>) -> Option<Self> {
        initialized
            .pool
            .connect(initialized.clock)
            .map(|client| Self(client, marker::PhantomData))
    }
}

const _: () = assert!(mem::size_of::<Pooled<'static, 0>>() == 2 * mem::size_of::<usize>());
