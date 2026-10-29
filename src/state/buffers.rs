use crate::error;
use dope::net;
use o3::{
    alloc,
    buffer::{pool, pool::owners, storage},
};

/// Exclusive receive storage transferred from pool admission to one read.
#[repr(transparent)]
pub struct Reserve<'d>(pool::Span<owners::Plain, pool::Borrowed<'d>>);

impl<'d> Reserve<'d> {
    pub(super) fn copy(
        mut self,
        plain: &[u8],
    ) -> Result<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'d>>>, error::Error>
    {
        self.0
            .try_append(plain)
            .map_err(|cause| error::Error::Consume {
                buffer: net::BufferKind::Receive,
                cause,
            })?
            .commit();
        Ok(self.0.freeze())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Release {
    Released,
    Retained,
}

pub(crate) enum Receive {
    Fixed(pool::Pool),
    Growing(pool::Growing),
}

impl Receive {
    pub(crate) fn available(&self) -> usize {
        match self {
            Self::Fixed(pool) => pool.available(),
            Self::Growing(pool) => pool.available(),
        }
    }
}

pub(crate) struct Buffers<'d> {
    recv_pool: &'d Receive,
    pending_pool: &'d pool::Pool,
}

impl<'d> Buffers<'d> {
    pub(crate) fn new(recv: &'d Receive, send: &'d pool::Pool) -> Self {
        Self {
            recv_pool: recv,
            pending_pool: send,
        }
    }

    pub(crate) fn send_pool(&self) -> &'d pool::Pool {
        self.pending_pool
    }
    pub(crate) fn try_reserve(&self) -> Result<Option<Reserve<'d>>, alloc::Exhausted> {
        let recv = match self.recv_pool {
            Receive::Fixed(pool) => pool.borrow(),
            Receive::Growing(pool) => pool.try_borrow()?,
        };
        Ok(recv.map(Reserve))
    }
}
