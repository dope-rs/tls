use std::{num, ops, option};

#[doc(hidden)]
pub mod policy;
mod sealed;
#[doc(hidden)]
pub mod waiters;

use dope::core::io::recv;
use dope::net::wire::{self, batch};
use o3::buffer::{bytes, resident};

use crate::state::api::capabilities::Status as _;
use crate::state::{direct, status};
use crate::tls::{self, connection, roles};

pub struct Batch<'a> {
    owned: option::IntoIter<bytes::Bytes<bytes::Pooled<'a>>>,
    plain: Option<direct::PlainChunks<'a>>,
}

impl<'a> Batch<'a> {
    fn new(
        owned: Option<bytes::Bytes<bytes::Pooled<'a>>>,
        plain: Option<direct::PlainChunks<'a>>,
    ) -> Self {
        Self {
            owned: owned.into_iter(),
            plain,
        }
    }
}

impl<'a> Iterator for Batch<'a> {
    type Item = wire::RecvChunk<'a, bytes::Bytes<bytes::Pooled<'a>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(chunk) = self.owned.next() {
            return Some(wire::RecvChunk::Owned(chunk));
        }
        self.plain.as_mut()?.next().map(|chunk| {
            wire::RecvChunk::Borrowed(bytes::Bytes::<bytes::Borrowed<'a>>::from(chunk))
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for Batch<'_> {
    fn len(&self) -> usize {
        self.owned.len() + self.plain.as_ref().map_or(0, ExactSizeIterator::len)
    }
}

struct Provided<'d> {
    bytes: recv::Shared<'d>,
    cursor: direct::PlainCursor,
}

impl Provided<'_> {
    fn remaining(&self) -> usize {
        self.cursor.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.cursor.chunk(self.bytes.as_slice())
    }

    fn consume(&mut self, requested: usize) -> usize {
        self.cursor.consume(self.bytes.as_slice(), requested)
    }
}

pub struct Retained<'d> {
    staged: Option<bytes::Bytes<bytes::Pooled<'d>>>,
    credit: Option<wire::ErasedRecvCreditGuard<'d>>,
    provided: Option<Provided<'d>>,
    remaining: usize,
}

impl<'d> Retained<'d> {
    fn new(
        staged: Option<bytes::Bytes<bytes::Pooled<'d>>>,
        provided: Option<Provided<'d>>,
    ) -> Option<Self> {
        let staged = staged.filter(|chunk| !chunk.is_empty());
        let provided = provided.filter(|chunk| chunk.remaining() != 0);
        let remaining = staged.as_ref().map_or(0, bytes::Bytes::len)
            + provided.as_ref().map_or(0, Provided::remaining);
        (remaining != 0).then_some(Self {
            staged,
            credit: None,
            provided,
            remaining,
        })
    }

    pub(super) fn bind_recv_credit<'recv, const ID: u8>(
        &'recv mut self,
        credit: wire::RecvCredit<'d, ID>,
    ) -> Result<wire::RecvCreditReceipt<'d, ID>, wire::RecvCredit<'d, ID>> {
        if self.staged.is_none() || self.credit.is_some() {
            return Err(credit);
        }
        match credit.claim() {
            Ok(credit) => {
                let (guard, receipt) = credit.erase();
                self.credit = Some(guard);
                Ok(receipt)
            }
            Err(credit) => Err(credit),
        }
    }
}

impl<'d> wire::Cursor<'d> for Retained<'d> {
    fn chunk(&self) -> &[u8] {
        if let Some(staged) = self.staged.as_ref() {
            return staged.as_slice();
        }
        self.provided.as_ref().map_or(&[], Provided::chunk)
    }

    fn consume(&mut self, requested: usize) -> usize {
        let consumed = if let Some(staged) = self.staged.as_mut() {
            let consumed = wire::Cursor::consume(staged, requested);
            if staged.is_empty() {
                self.staged = None;
                self.credit = None;
            }
            consumed
        } else if let Some(provided) = self.provided.as_mut() {
            let consumed = provided.consume(requested);
            if provided.remaining() == 0 {
                self.provided = None;
            }
            consumed
        } else {
            0
        };
        self.remaining -= consumed;
        consumed
    }

    fn remaining(&self) -> usize {
        self.remaining
    }

    fn retain(
        &self,
        range: ops::Range<usize>,
        budget: &resident::Budget<'d>,
    ) -> Result<wire::RetainedBytes<'d>, wire::RetainError> {
        if let Some(staged) = self.staged.as_ref() {
            let retained = staged
                .clone()
                .get(range)
                .map(wire::RetainedBytes::from_pooled)
                .ok_or(wire::RetainError::Range)?;
            return Ok(match self.credit.as_ref() {
                Some(credit) => retained.with_credit(credit.clone()),
                None => retained,
            });
        }
        let provided = &self
            .provided
            .as_ref()
            .ok_or(wire::RetainError::Range)?
            .bytes;
        provided
            .as_slice()
            .get(range.clone())
            .ok_or(wire::RetainError::Range)?;
        provided
            .accounted(range, budget)
            .map(wire::RetainedBytes::from_provided)
            .ok_or(wire::RetainError::Capacity)
    }
}

pub(super) struct IngressResult<'a, 'd> {
    staged: Option<bytes::Bytes<bytes::Pooled<'d>>>,
    plain: Option<direct::PlainChunks<'a>>,
    plain_offset: usize,
}

impl<'a, 'd: 'a> IngressResult<'a, 'd> {
    fn into_batch(self) -> Batch<'a> {
        Batch::new(self.staged, self.plain)
    }

    fn retain(self) -> RetainedResult<'d> {
        RetainedResult {
            staged: self.staged,
            layout: self.plain.map(direct::PlainChunks::into_layout),
            plain_offset: self.plain_offset,
        }
    }
}

pub(super) struct RetainedResult<'d> {
    staged: Option<bytes::Bytes<bytes::Pooled<'d>>>,
    layout: Option<direct::PlainLayout>,
    plain_offset: usize,
}

impl<'pool> RetainedResult<'pool> {
    pub(super) fn into_cursor<'d>(self, mut bytes: recv::Lease<'d>) -> Option<Retained<'d>>
    where
        'pool: 'd,
    {
        let provided = self.layout.and_then(|layout| {
            (layout.plain_len() != 0).then(|| {
                bytes.advance(self.plain_offset);
                Provided {
                    cursor: layout.cursor(),
                    bytes: bytes.into_shared(),
                }
            })
        });
        Retained::new(self.staged, provided)
    }
}

pub(super) struct Ingress<'s, 'd, R: roles::Protocol, const ID: u8> {
    connection: &'s mut connection::ConnectionState<'d, R::Session<'d, ID>>,
    role: &'s mut R::Runtime<'d, ID>,
}

#[derive(Clone, Copy)]
enum Delivery {
    Batch(num::NonZeroUsize),
    Retained,
}

impl<'s, 'd, R: roles::Protocol, const ID: u8> Ingress<'s, 'd, R, ID> {
    pub(super) fn new(
        connection: &'s mut connection::ConnectionState<'d, R::Session<'d, ID>>,
        role: &'s mut R::Runtime<'d, ID>,
    ) -> Self {
        Self { connection, role }
    }

    pub(super) fn read_batch<'a>(
        self,
        bytes: &'a mut [u8],
        capacity: &batch::Capacity<tls::Tls<R>>,
    ) -> Batch<'a>
    where
        'd: 'a,
    {
        self.read(bytes, Delivery::Batch(capacity.items()))
            .into_batch()
    }

    pub(super) fn read_retained(self, bytes: &mut [u8]) -> RetainedResult<'d> {
        self.read(bytes, Delivery::Retained).retain()
    }

    fn read<'a>(self, bytes: &'a mut [u8], delivery: Delivery) -> IngressResult<'a, 'd> {
        let mut staged = None;
        let direct_offset = if self.connection.tls.has_staged_recv() {
            let read = R::read_staged::<ID>(&mut self.connection.tls, self.role, bytes);
            let consumed = read.consumed();
            let status = read.status();
            staged = read.into_chunk();
            match status {
                status::Read::Continue
                    if consumed < bytes.len() && !self.connection.tls.has_staged_recv() =>
                {
                    Some(consumed)
                }
                status::Read::Failed => {
                    self.connection.close = true;
                    None
                }
                status::Read::Continue | status::Read::Stop => None,
            }
        } else {
            Some(0)
        };

        let plain = direct_offset.and_then(|offset| {
            let limit = match delivery {
                Delivery::Retained => None,
                Delivery::Batch(capacity) => {
                    let occupied = usize::from(staged.is_some());
                    let Some(available) = capacity
                        .get()
                        .checked_sub(occupied)
                        .and_then(num::NonZeroUsize::new)
                    else {
                        self.connection.close = true;
                        return None;
                    };
                    Some(available)
                }
            };
            let read = R::read_direct::<ID>(
                &mut self.connection.tls,
                self.role,
                &mut bytes[offset..],
                limit,
            );
            if read.status() == status::Read::Failed {
                self.connection.close = true;
            }
            Some(read.into_plain())
        });
        if self.connection.tls.is_closed()
            && self.connection.tls.peer_close() != status::PeerClose::CloseNotify
        {
            self.connection.close = true;
        }
        IngressResult {
            staged,
            plain,
            plain_offset: direct_offset.unwrap_or(0),
        }
    }
}
