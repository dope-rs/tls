use std::{
    io::{self, ErrorKind},
    mem,
    ops::Range,
};

use dope_net::wire::buffered::{Buffer, Buffered, FillError, Recv, RecvPool, Scratch};
use dope_net::{Bytes, Leased};
use shin::record::{ContentType, PlaintextRecord, RecordError};

use crate::{error::Error, staging::TLS_STAGING_CAP};

const INCOMING_APP_CAP: usize = 1 << 20;

enum Incoming {
    Owned(Vec<u8>),
    Pooled {
        pool: RecvPool,
        data: Option<Buffer<Recv>>,
    },
}

impl Incoming {
    fn extend(&mut self, bytes: &[u8]) -> bool {
        match self {
            Self::Owned(data) => {
                if data
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|required| required > INCOMING_APP_CAP)
                {
                    return false;
                }
                data.extend_from_slice(bytes);
                true
            }
            Self::Pooled { pool, data } => {
                if data.is_none() {
                    *data = pool.try_acquire();
                }
                let Some(data) = data else {
                    return false;
                };
                if data
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|required| required > data.capacity())
                {
                    return false;
                }
                data.try_extend_from_slice(bytes).is_ok()
            }
        }
    }

    fn take_vec(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Owned(data) if !data.is_empty() => Some(mem::take(data)),
            Self::Owned(_) => None,
            Self::Pooled { data, .. } => data.take().map(|data| data.as_slice().to_vec()),
        }
    }

    fn take_leased(&mut self) -> Option<Bytes<Leased>> {
        match self {
            Self::Owned(_) => None,
            Self::Pooled { data, .. } => data.take().map(Buffer::freeze),
        }
    }
}

pub(crate) struct Buffers {
    recv: Buffer<Scratch>,
    pending: Buffer<Scratch>,
    incoming: Incoming,
}

impl Buffers {
    pub(crate) fn try_runtime(runtime: &Buffered) -> Option<Self> {
        Some(Self {
            recv: runtime.try_acquire_scratch()?,
            pending: runtime.try_acquire_scratch()?,
            incoming: Incoming::Pooled {
                pool: runtime.recv_pool(),
                data: None,
            },
        })
    }

    pub(super) fn standalone() -> Result<Self, Error> {
        let runtime = Buffered::try_fixed(2, TLS_STAGING_CAP, 0, 1)
            .map_err(|error| Error::Io(io::Error::new(ErrorKind::InvalidInput, error)))?;
        Ok(Self {
            recv: runtime
                .try_acquire_scratch()
                .ok_or(Error::BufferUnavailable)?,
            pending: runtime
                .try_acquire_scratch()
                .ok_or(Error::BufferUnavailable)?,
            incoming: Incoming::Owned(Vec::new()),
        })
    }

    pub(super) fn append_recv(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let take = bytes.len().min(self.recv.spare_capacity());
        self.recv
            .try_extend_from_slice(&bytes[..take])
            .map_err(|_| Error::ReceiveOverflow)?;
        Ok(take)
    }

    pub(super) fn recv(&self) -> &[u8] {
        self.recv.as_slice()
    }

    pub(super) fn recv_mut(&mut self) -> &mut [u8] {
        self.recv.as_mut_slice()
    }

    pub(super) fn consume_recv(&mut self, n: usize) {
        self.recv.consume(n);
    }

    pub(super) fn pending(&self) -> &[u8] {
        self.pending.as_slice()
    }

    pub(super) fn pending_mut(&mut self) -> &mut Buffer<Scratch> {
        &mut self.pending
    }

    pub(super) fn pending_spare(&self) -> usize {
        self.pending.spare_capacity()
    }

    pub(super) fn consume_pending(&mut self, n: usize) {
        self.pending.consume(n);
    }

    pub(super) fn take_pending(&mut self) -> Vec<u8> {
        let data = self.pending.as_slice().to_vec();
        self.pending.consume(data.len());
        data
    }

    pub(super) fn encode_plaintext(
        &mut self,
        content_type: ContentType,
        data: &[u8],
    ) -> Result<(), Error> {
        self.pending
            .try_fill(|spare| PlaintextRecord::encode_into_uninit(content_type, data, spare))
            .map_err(Self::fill_error)
    }

    pub(super) fn extend_incoming(&mut self, range: Range<usize>) -> bool {
        self.incoming.extend(&self.recv.as_slice()[range])
    }

    pub(super) fn take_vec(&mut self) -> Option<Vec<u8>> {
        self.incoming.take_vec()
    }

    pub(super) fn take_leased(&mut self) -> Option<Bytes<Leased>> {
        self.incoming.take_leased()
    }

    pub(super) fn fill_error(error: FillError<RecordError>) -> Error {
        match error {
            FillError::Fill(RecordError::BufferTooSmall) | FillError::Capacity => {
                Error::SendOverflow
            }
            FillError::Fill(error) => Error::Record(error),
        }
    }
}
