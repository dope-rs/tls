use std::{mem, num};

use dope::net::{self, wire::domain};
use o3::{base::num::bounded, buffer::pool};

use crate::staging;

const DEFAULT_STAGED_RECORDS: usize = 64;
const DEFAULT_CIPHERTEXT_SLOTS: usize = 128;
const MAX_STAGED_RECORDS: u32 = u32::MAX - 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Staged { actual: usize, maximum: usize },
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Staged(bounded::U32<0, MAX_STAGED_RECORDS>);

impl Staged {
    pub const fn fixed<const COUNT: u32>() -> Self {
        Self(bounded::U32::exact::<COUNT>())
    }

    const fn get(self) -> usize {
        self.0.into_usize()
    }
}

impl TryFrom<usize> for Staged {
    type Error = Error;

    fn try_from(actual: usize) -> Result<Self, Self::Error> {
        match bounded::U32::from_usize(actual) {
            Some(count) => Ok(Self(count)),
            None => Err(Error::Staged {
                actual,
                maximum: MAX_STAGED_RECORDS as usize,
            }),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Plan {
    staged: Option<Staged>,
    send: Option<num::NonZero<usize>>,
    growing: Option<num::NonZero<u32>>,
}

impl Plan {
    pub(super) const fn new() -> Self {
        Self {
            staged: None,
            send: None,
            growing: None,
        }
    }

    pub(super) const fn with_staged(mut self, max: Staged) -> Self {
        self.staged = Some(max);
        self
    }

    pub(super) const fn with_send(mut self, max: num::NonZero<usize>) -> Self {
        self.send = Some(max);
        self
    }

    pub(super) const fn with_growth(mut self, warm: num::NonZero<u32>) -> Self {
        self.growing = Some(warm);
        self
    }

    /// Staged counts and record-divided resident bytes leave room for one receive slot.
    pub fn layout(self, limits: domain::Limits) -> Result<Layout, net::Resource> {
        let cap = limits.connections().nonzero();
        let held = match self.staged {
            Some(staged) => staged.get(),
            None => DEFAULT_STAGED_RECORDS.min(cap.get()).max(
                limits
                    .resident()
                    .into_raw()
                    .div_ceil(staging::MAX_PLAINTEXT),
            ),
        };
        let recv = held + 1;
        let limit = match self.send {
            Some(send) => send,
            None => num::NonZero::<usize>::MIN.saturating_add(DEFAULT_CIPHERTEXT_SLOTS - 1),
        };
        let send = limit.min(cap).get();
        Layout::try_new(recv, send, self.growing)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Layout {
    pub(super) recv: pool::Layout,
    pub(super) send: pool::Layout,
    pub(super) growing: Option<num::NonZero<u32>>,
}

impl Layout {
    fn try_new(
        rslots: usize,
        sslots: usize,
        growing: Option<num::NonZero<u32>>,
    ) -> Result<Self, net::Resource> {
        let recv = pool::Layout::new(rslots, staging::MAX_PLAINTEXT).map_err(|cause| {
            net::Resource::BufferLayout(net::BufferLayout::new(net::BufferKind::Receive, cause))
        })?;
        let send = pool::Layout::new(sslots, staging::TLS_STAGING_CAP).map_err(|cause| {
            net::Resource::BufferLayout(net::BufferLayout::new(net::BufferKind::Send, cause))
        })?;
        Ok(Self {
            recv,
            send,
            growing,
        })
    }

    pub fn recv_slots(self) -> u32 {
        self.recv.slots()
    }

    pub fn send_slots(self) -> u32 {
        self.send.slots()
    }

    pub fn recv_cap(self) -> usize {
        staging::MAX_PLAINTEXT
    }

    pub fn send_cap(self) -> usize {
        staging::TLS_STAGING_CAP
    }

    /// Returns the maximum pool payload bytes without allocator or pool metadata.
    /// Growing receive pools allocate only their warm group when bound.
    pub fn payload(self) -> usize {
        self.recv.slots() as usize * staging::MAX_PLAINTEXT
            + self.send.slots() as usize * staging::TLS_STAGING_CAP
    }
}

const _: () = assert!(mem::size_of::<Staged>() == mem::size_of::<u32>());
const _: () = {
    assert!(staging::MAX_PLAINTEXT > 1);
    assert!(
        u32::MAX as u128 * (staging::MAX_PLAINTEXT as u128 + staging::TLS_STAGING_CAP as u128)
            <= usize::MAX as u128
    );
};
