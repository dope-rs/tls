use std::iter;

use dope::net::wire::{reclaim, send};
use o3::buffer;

pub(crate) struct VectoredCursor<'a, I>
where
    I: Iterator<Item = &'a [u8]>,
{
    source: I,
    current: &'a [u8],
    consumed: usize,
}

impl<'a, I> VectoredCursor<'a, I>
where
    I: Iterator<Item = &'a [u8]>,
{
    pub(crate) fn new(source: I) -> Self {
        Self {
            source,
            current: &[],
            consumed: 0,
        }
    }

    pub(crate) fn take(&mut self, len: usize) -> impl Iterator<Item = &'a [u8]> + '_ {
        let mut remaining = len;
        iter::from_fn(move || {
            if remaining == 0 {
                return None;
            }
            let part = self.next_part(remaining)?;
            remaining -= part.len();
            Some(part)
        })
    }

    pub(crate) fn consumed(&self) -> usize {
        self.consumed
    }

    fn next_part(&mut self, max: usize) -> Option<&'a [u8]> {
        while self.current.is_empty() {
            self.current = self.source.next()?;
        }
        let take = self.current.len().min(max);
        let (part, rest) = self.current.split_at(take);
        self.current = rest;
        self.consumed += take;
        Some(part)
    }
}

pub(crate) trait SendProtocol {
    type Storage: SendBuffer;

    fn try_buffer<'a>(
        &self,
        storage: &'a mut Self::Storage,
    ) -> Option<&'a mut <Self::Storage as SendBuffer>::Cursor>;
    fn needs_buffer(&self) -> bool {
        false
    }
    fn encrypt(
        &mut self,
        egress: &mut <Self::Storage as SendBuffer>::Cursor,
        plain: &[u8],
    ) -> usize;
    fn encrypt_vectored(
        &mut self,
        egress: &mut <Self::Storage as SendBuffer>::Cursor,
        vectored: &send::Vectored<'_>,
    ) -> usize;
    fn propagate_close(&mut self, egress: &mut <Self::Storage as SendBuffer>::Cursor) -> bool;
    fn drain_to_egress(&mut self, _egress: &mut <Self::Storage as SendBuffer>::Cursor) {}
    fn send_inflight(&mut self) -> &mut bool;
}

pub(crate) trait SendBuffer: send::StorageBackend {
    type Cursor: buffer::PrefixConsumer;

    fn buffer_mut(&mut self) -> Option<&mut Self::Cursor>;
    fn release_if_empty(&mut self) -> send::Availability {
        send::Availability::Unchanged
    }
}

pub(crate) struct Sender<'a, P> {
    protocol: &'a mut P,
}

impl<'a, P: SendProtocol> Sender<'a, P> {
    pub(crate) fn new(protocol: &'a mut P) -> Self {
        Self { protocol }
    }

    pub(crate) fn prepare<'b>(
        &mut self,
        mut send: send::Storage<'b, P::Storage>,
        plain: send::Plain<'b>,
    ) -> send::Prepared<'b, reclaim::OnSubmit> {
        if plain.is_empty() && send.as_slice().is_empty() && !self.protocol.needs_buffer() {
            return send.empty();
        }
        let Some(egress) = self.protocol.try_buffer(&mut send) else {
            return send.empty();
        };
        self.protocol.drain_to_egress(egress);
        let consumed = if self.protocol.needs_buffer() {
            0
        } else {
            self.protocol.encrypt(egress, plain.as_slice())
        };
        let close = self.protocol.propagate_close(egress);
        self.finish(send, consumed, close)
    }

    pub(crate) fn prepare_vectored<'b>(
        &mut self,
        mut send: send::Storage<'b, P::Storage>,
        vectored: send::Vectored<'b>,
    ) -> send::Prepared<'b, reclaim::OnSubmit> {
        if vectored.is_empty() && send.as_slice().is_empty() && !self.protocol.needs_buffer() {
            return send.empty();
        }
        let Some(egress) = self.protocol.try_buffer(&mut send) else {
            return send.empty();
        };
        self.protocol.drain_to_egress(egress);
        let consumed = if self.protocol.needs_buffer() {
            0
        } else {
            self.protocol.encrypt_vectored(egress, &vectored)
        };
        let close = self.protocol.propagate_close(egress);
        self.finish(send, consumed, close)
    }

    pub(crate) fn after_send<'b>(
        &mut self,
        mut send: send::Storage<'b, P::Storage>,
        sent: send::Sent,
    ) -> send::Transition<'b, reclaim::OnSubmit> {
        use o3::buffer::PrefixConsumer;

        *self.protocol.send_inflight() = false;
        let Some(egress) = send.buffer_mut() else {
            return send::Transition::unchanged(send.empty());
        };
        let Ok(prefix) = PrefixConsumer::try_consume_prefix(egress, sent.get()) else {
            return send::Transition::unchanged(send.empty().close_after());
        };
        prefix.commit();
        self.protocol.drain_to_egress(egress);
        let close = self.protocol.propagate_close(egress);
        let availability = send.release_if_empty();
        let prepared = self.finalize(send, 0, close);
        send::Transition::new(prepared, availability)
    }

    pub(crate) fn flush<'b>(
        &mut self,
        mut send: send::Storage<'b, P::Storage>,
    ) -> send::Prepared<'b, reclaim::OnSubmit> {
        if send.as_slice().is_empty() && !self.protocol.needs_buffer() {
            return send.empty();
        }
        let Some(egress) = self.protocol.try_buffer(&mut send) else {
            return send.empty();
        };
        self.protocol.drain_to_egress(egress);
        let close = self.protocol.propagate_close(egress);
        self.finish(send, 0, close)
    }

    pub(crate) fn finish<'b>(
        &mut self,
        mut send: send::Storage<'b, P::Storage>,
        consumed: usize,
        close: bool,
    ) -> send::Prepared<'b, reclaim::OnSubmit> {
        let _ = send.release_if_empty();
        self.finalize(send, consumed, close)
    }

    fn finalize<'b>(
        &mut self,
        send: send::Storage<'b, P::Storage>,
        consumed: usize,
        close: bool,
    ) -> send::Prepared<'b, reclaim::OnSubmit> {
        *self.protocol.send_inflight() = !send.as_slice().is_empty();
        let prepared = send.buffered(consumed);
        if close {
            prepared.close_after()
        } else {
            prepared
        }
    }
}
