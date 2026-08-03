use std::option::IntoIter;

use dope_net::wire::{Lease, RecvChunk, RecvCredit, RecvCreditGuard, RecvCursor, RecvTarget};
use dope_net::{Borrowed, Bytes, Retained};

use crate::state::direct::{PlainChunks, PlainCursor, PlainLayout};
use crate::state::status::PeerClose;

use super::{ConnectionState, Role};

pub struct TlsRecvBatch<'a> {
    owned: IntoIter<Bytes<Retained>>,
    plain: Option<PlainChunks<'a>>,
}

impl<'a> TlsRecvBatch<'a> {
    fn new(owned: Option<Bytes<Retained>>, plain: Option<PlainChunks<'a>>) -> Self {
        Self {
            owned: owned.into_iter(),
            plain,
        }
    }
}

impl<'a> Iterator for TlsRecvBatch<'a> {
    type Item = RecvChunk<'a, Bytes<Retained>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(chunk) = self.owned.next() {
            return Some(RecvChunk::Owned(chunk));
        }
        self.plain
            .as_mut()?
            .next()
            .map(|chunk| RecvChunk::Borrowed(Bytes::<Borrowed<'a>>::from(chunk)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for TlsRecvBatch<'_> {
    fn len(&self) -> usize {
        self.owned.len() + self.plain.as_ref().map_or(0, ExactSizeIterator::len)
    }
}

struct TlsProvided<'d> {
    bytes: Lease<'d>,
    cursor: PlainCursor,
}

impl TlsProvided<'_> {
    fn remaining(&self) -> usize {
        self.cursor.remaining()
    }

    fn read_into(&mut self, target: &mut RecvTarget<'_>) {
        self.cursor.read_into(self.bytes.as_slice(), target);
    }
}

pub struct TlsRetained<'d> {
    staged: Option<Bytes<Retained>>,
    credit: Option<RecvCreditGuard<'d>>,
    provided: Option<TlsProvided<'d>>,
    remaining: usize,
}

impl<'d> TlsRetained<'d> {
    fn new(staged: Option<Bytes<Retained>>, provided: Option<TlsProvided<'d>>) -> Option<Self> {
        let staged = staged.filter(|chunk| !chunk.is_empty());
        let provided = provided.filter(|chunk| chunk.remaining() != 0);
        let remaining = staged.as_ref().map_or(0, Bytes::len)
            + provided.as_ref().map_or(0, TlsProvided::remaining);
        (remaining != 0).then_some(Self {
            staged,
            credit: None,
            provided,
            remaining,
        })
    }

    pub(super) fn bind_recv_credit(
        &mut self,
        credit: RecvCredit<'d>,
    ) -> Result<(), RecvCredit<'d>> {
        if self.staged.is_none() {
            return Err(credit);
        }
        debug_assert!(self.credit.is_none());
        match credit.claim() {
            Ok(credit) => {
                self.credit = Some(credit);
                Ok(())
            }
            Err(credit) => Err(credit),
        }
    }
}

impl RecvCursor for TlsRetained<'_> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn read_into(&mut self, target: &mut RecvTarget<'_>) {
        let initial = target.len();
        if let Some(staged) = self.staged.as_mut() {
            RecvCursor::read_into(staged, target);
            if staged.is_empty() {
                self.staged = None;
                self.credit = None;
            }
        }
        if target.remaining() != 0
            && let Some(provided) = self.provided.as_mut()
        {
            provided.read_into(target);
            if provided.remaining() == 0 {
                self.provided = None;
            }
        }
        let written = target.len() - initial;
        self.remaining -= written;
    }
}

pub(super) struct IngressResult<'a> {
    staged: Option<Bytes<Retained>>,
    plain: Option<PlainChunks<'a>>,
    plain_offset: usize,
}

impl<'a> IngressResult<'a> {
    pub(super) fn into_batch(self) -> TlsRecvBatch<'a> {
        TlsRecvBatch::new(self.staged, self.plain)
    }

    pub(super) fn retain(self) -> RetainedResult {
        RetainedResult {
            staged: self.staged,
            layout: self.plain.map(PlainChunks::into_layout),
            plain_offset: self.plain_offset,
        }
    }
}

pub(super) struct RetainedResult {
    staged: Option<Bytes<Retained>>,
    layout: Option<PlainLayout>,
    plain_offset: usize,
}

impl RetainedResult {
    pub(super) fn into_cursor<'d>(self, mut bytes: Lease<'d>) -> Option<TlsRetained<'d>> {
        let provided = self.layout.and_then(|layout| {
            (layout.plain_len() != 0).then(|| {
                bytes.advance(self.plain_offset);
                TlsProvided {
                    cursor: layout.cursor(),
                    bytes,
                }
            })
        });
        TlsRetained::new(self.staged, provided)
    }
}

pub(super) struct Ingress<'s, 'd, R: Role> {
    connection: &'s mut ConnectionState<R::Session<'d>>,
    role: &'s mut R::Runtime<'d>,
}

impl<'s, 'd, R: Role> Ingress<'s, 'd, R> {
    pub(super) fn new(
        connection: &'s mut ConnectionState<R::Session<'d>>,
        role: &'s mut R::Runtime<'d>,
    ) -> Self {
        Self { connection, role }
    }

    pub(super) fn read<'a>(self, bytes: &'a mut [u8]) -> IngressResult<'a> {
        let mut staged = None;
        let direct_offset = if self.connection.tls.has_staged_recv() {
            let (consumed, chunk, keep_reading, ok) =
                R::read_staged(&mut self.connection.tls, self.role, bytes);
            staged = chunk;
            if !ok {
                self.connection.close = true;
            }
            (ok && keep_reading && consumed < bytes.len() && !self.connection.tls.has_staged_recv())
                .then_some(consumed)
        } else {
            Some(0)
        };

        let plain = direct_offset.map(|offset| {
            let (plain, ok) =
                R::read_direct(&mut self.connection.tls, self.role, &mut bytes[offset..]);
            if !ok {
                self.connection.close = true;
            }
            plain
        });
        if self.connection.tls.is_closed()
            && self.connection.tls.peer_close() != PeerClose::CloseNotify
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
