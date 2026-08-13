use std::ops;

use crate::error;
use o3::buffer::PrefixConsumer as _;
use o3::buffer::{self, bytes, pool};

pub(super) struct ReceiveOverflow;

pub(super) enum Pending<'a, 'd> {
    Pooled {
        buffer: &'a mut Option<pool::BorrowedCursor<'d>>,
        pool: &'d buffer::Pool,
    },
    Borrowed(&'a mut pool::BorrowedCursor<'d>),
}

impl<'d> Pending<'_, 'd> {
    pub(super) fn try_buffer(&mut self) -> Option<&mut pool::BorrowedCursor<'d>> {
        match self {
            Self::Pooled { buffer, pool } => {
                if buffer.is_none() {
                    **buffer = pool.try_acquire_borrowed_buffer();
                }
                buffer.as_mut()
            }
            Self::Borrowed(buffer) => Some(buffer),
        }
    }
}

pub(crate) struct Buffers<'d> {
    recv: Option<pool::BorrowedCursor<'d>>,
    recv_pool: &'d buffer::Pool,
    pub(super) pending: Option<pool::BorrowedCursor<'d>>,
    pending_pool: &'d buffer::Pool,
}

impl<'d> Buffers<'d> {
    pub(crate) fn pooled(recv_pool: &'d buffer::Pool, pending_pool: &'d buffer::Pool) -> Self {
        Self {
            recv: None,
            recv_pool,
            pending: None,
            pending_pool,
        }
    }

    pub(crate) fn pooled_with_pending(
        recv_pool: &'d buffer::Pool,
        pending_pool: &'d buffer::Pool,
        pending: pool::BorrowedCursor<'d>,
    ) -> Self {
        Self {
            recv: None,
            recv_pool,
            pending: Some(pending),
            pending_pool,
        }
    }

    pub(super) fn append_recv(&mut self, bytes: &[u8]) -> Result<usize, ReceiveOverflow> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.recv.is_none() {
            self.recv = Some(
                self.recv_pool
                    .try_acquire_borrowed_buffer()
                    .ok_or(ReceiveOverflow)?,
            );
        }
        let recv = self.recv.as_mut().ok_or(ReceiveOverflow)?;
        let take = bytes.len().min(recv.spare_capacity());
        recv.try_extend(&bytes[..take])
            .map_err(|_| ReceiveOverflow)?;
        Ok(take)
    }

    pub(super) fn recv(&self) -> &[u8] {
        self.recv.as_ref().map_or(&[], |cursor| cursor.as_slice())
    }

    pub(super) fn recv_record_and_pending(
        &mut self,
        total: usize,
    ) -> Result<(&mut [u8], Pending<'_, 'd>), error::Error> {
        let recv = self.recv.as_mut().ok_or(error::Error::BufferUnavailable)?;
        Ok((
            &mut recv.as_mut_slice()[..total],
            Pending::Pooled {
                buffer: &mut self.pending,
                pool: self.pending_pool,
            },
        ))
    }

    pub(super) fn try_consume_recv(&mut self, n: usize) -> bool {
        let Some(recv) = self.recv.as_mut() else {
            return n == 0;
        };
        let Ok(prefix) = recv.try_consume_prefix(n) else {
            return false;
        };
        prefix.commit();
        if recv.is_empty() {
            self.recv = None;
        }
        true
    }

    pub(super) fn take_recv_range(
        &mut self,
        range: ops::Range<usize>,
    ) -> Option<bytes::Bytes<bytes::Pooled<'d>>> {
        self.recv.take()?.freeze().get(range)
    }

    pub(super) fn pending(&self) -> &[u8] {
        self.pending
            .as_ref()
            .map_or(&[], |cursor| cursor.as_slice())
    }

    pub(super) fn pending_output(&mut self) -> Pending<'_, 'd> {
        Pending::Pooled {
            buffer: &mut self.pending,
            pool: self.pending_pool,
        }
    }

    pub(super) fn pending_spare(&self) -> usize {
        self.pending.as_ref().map_or_else(
            || self.pending_pool.capacity(),
            |cursor| cursor.spare_capacity(),
        )
    }

    pub(super) fn pending_pool(&self) -> &'d buffer::Pool {
        self.pending_pool
    }

    pub(super) fn try_consume_pending(&mut self, n: usize) -> bool {
        let Some(pending) = self.pending.as_mut() else {
            return n == 0;
        };
        let Ok(prefix) = pending.try_consume_prefix(n) else {
            return false;
        };
        prefix.commit();
        if pending.is_empty() {
            self.pending = None;
        }
        true
    }

    pub(crate) fn reserve_recv(&mut self) -> bool {
        if self.recv.is_none() {
            self.recv = self.recv_pool.try_acquire_borrowed_buffer();
        }
        self.recv.is_some()
    }

    pub(crate) fn release_recv_if_empty(&mut self) -> bool {
        let released = self.recv.as_ref().is_some_and(|cursor| cursor.is_empty());
        if released {
            self.recv = None;
        }
        released
    }
}
