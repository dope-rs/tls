use core::mem;
use std::{cell, io};

use o3::collections::slab;
use shin::connection;
use shin::server::{self, config, workspace};
use shin::wire::handshake;

use crate::clock;
use crate::state::sessions;

#[doc(hidden)]
pub struct Storage<
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
> {
    capacity: slab::Capacity,
    initialized: cell::OnceCell<Initialized<DOMAIN, G, V>>,
}

struct Initialized<const DOMAIN: u8, G: config::EarlyDataGuard, V: config::ClientCertVerifier> {
    pool: workspace::Pool<clock::Clock, V, DOMAIN, G>,
}

impl<G, V, const DOMAIN: u8> Storage<DOMAIN, G, V>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(crate) fn new(capacity: slab::Capacity) -> Self {
        Self {
            capacity,
            initialized: cell::OnceCell::new(),
        }
    }

    pub(crate) fn bind(
        &self,
        shard: &server::Shard<G, V, DOMAIN>,
    ) -> io::Result<&workspace::Pool<clock::Clock, V, DOMAIN, G>> {
        if let Some(initialized) = self.initialized.get() {
            return if initialized.pool.matches_shard(shard) {
                Ok(&initialized.pool)
            } else {
                Err(profile_mismatch())
            };
        }
        let pool = shard.tls_profile().into_pool::<clock::Clock>(self.capacity);
        let initialized = Initialized { pool };
        self.initialized
            .set(initialized)
            .map_err(|_| profile_mismatch())?;
        Ok(&self.initialized.get().ok_or_else(profile_mismatch)?.pool)
    }
}

fn profile_mismatch() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TLS session storage is already bound to another server shard",
    )
}

#[doc(hidden)]
pub struct Pooled<
    'd,
    const DOMAIN: u8 = 0,
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
>(server::PooledConnection<'d, clock::Clock, DOMAIN, V, G>);

impl<G, V, const DOMAIN: u8> sessions::Peer for Pooled<'_, DOMAIN, G, V>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    fn selected_alpn(&self) -> Option<&[u8]> {
        self.0.selected_alpn()
    }

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
}

impl<G, V, const DOMAIN: u8> sessions::ServerPeer for Pooled<'_, DOMAIN, G, V>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>> {
        self.0.read_into(epoch, data, events)
    }
}

impl<'d, G, V, const DOMAIN: u8> Pooled<'d, DOMAIN, G, V>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(in crate::state) fn new_tls(
        pool: &'d workspace::Pool<clock::Clock, V, DOMAIN, G>,
        clock: clock::Clock,
    ) -> Option<Self> {
        pool.connect(clock).map(Self)
    }
}

const _: () = assert!(mem::size_of::<Pooled<'static>>() == 2 * mem::size_of::<usize>());
