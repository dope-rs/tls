use std::{
    io::{self, ErrorKind},
    ops::Range,
};

use dope_net::wire::buffered::{Buffer, Buffered, FillError, Scratch, ScratchPool};
use dope_net::{Bytes, Retained};
use shin::wire::record::RecordError;

use crate::{error::Error, staging::TLS_STAGING_CAP};

pub(super) struct ReceiveOverflow;

pub(super) struct Pending<'a> {
    buffer: &'a mut Option<Buffer<Scratch>>,
    pool: &'a ScratchPool,
}

impl Pending<'_> {
    pub(super) fn try_buffer(&mut self) -> Option<&mut Buffer<Scratch>> {
        if self.buffer.is_none() {
            *self.buffer = self.pool.try_acquire();
        }
        self.buffer.as_mut()
    }
}

pub(crate) struct Buffers {
    recv: Option<Buffer<Scratch>>,
    recv_pool: ScratchPool,
    pending: Option<Buffer<Scratch>>,
    pending_pool: ScratchPool,
}

impl Buffers {
    pub(crate) fn from_runtime(runtime: &Buffered) -> Self {
        let pool = runtime.scratch_pool();
        Self::pooled(pool.clone(), pool)
    }

    pub(crate) fn pooled(recv_pool: ScratchPool, pending_pool: ScratchPool) -> Self {
        Self {
            recv: None,
            recv_pool,
            pending: None,
            pending_pool,
        }
    }

    pub(crate) fn with_pending(
        recv_pool: ScratchPool,
        pending_pool: ScratchPool,
        pending: Buffer<Scratch>,
    ) -> Self {
        Self {
            recv: None,
            recv_pool,
            pending: Some(pending),
            pending_pool,
        }
    }

    pub(super) fn standalone() -> Result<Self, Error> {
        let pool = ScratchPool::try_new(2, TLS_STAGING_CAP)
            .map_err(|error| Error::Io(io::Error::new(ErrorKind::InvalidInput, error)))?;
        Ok(Self::pooled(pool.clone(), pool))
    }

    pub(super) fn append_recv(&mut self, bytes: &[u8]) -> Result<usize, ReceiveOverflow> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let recv = self.recv_mut()?;
        let take = bytes.len().min(recv.spare_capacity());
        recv.try_extend_from_slice(&bytes[..take])
            .map_err(|_| ReceiveOverflow)?;
        Ok(take)
    }

    pub(super) fn recv(&self) -> &[u8] {
        self.recv.as_ref().map_or(&[], Buffer::as_slice)
    }

    pub(super) fn recv_record_and_pending(
        &mut self,
        total: usize,
    ) -> Result<(&mut [u8], Pending<'_>), Error> {
        let recv = self.recv.as_mut().ok_or(Error::BufferUnavailable)?;
        Ok((
            &mut recv.as_mut_slice()[..total],
            Pending {
                buffer: &mut self.pending,
                pool: &self.pending_pool,
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

    pub(super) fn take_recv_range(&mut self, range: Range<usize>) -> Option<Bytes<Retained>> {
        self.recv.take()?.freeze_range(range)
    }

    pub(super) fn pending(&self) -> &[u8] {
        self.pending.as_ref().map_or(&[], Buffer::as_slice)
    }

    pub(super) fn pending_output(&mut self) -> Pending<'_> {
        Pending {
            buffer: &mut self.pending,
            pool: &self.pending_pool,
        }
    }

    pub(super) fn pending_spare(&self) -> usize {
        self.pending
            .as_ref()
            .map_or_else(|| self.pending_pool.capacity(), Buffer::spare_capacity)
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

    pub(super) fn fill_error(error: FillError<RecordError>) -> Error {
        match error {
            FillError::Fill(RecordError::BufferTooSmall) | FillError::Capacity => {
                Error::SendOverflow
            }
            FillError::Fill(error) => Error::Record(error),
        }
    }

    fn recv_mut(&mut self) -> Result<&mut Buffer<Scratch>, ReceiveOverflow> {
        if self.recv.is_none() {
            self.recv = Some(self.recv_pool.try_acquire().ok_or(ReceiveOverflow)?);
        }
        self.recv.as_mut().ok_or(ReceiveOverflow)
    }
}
