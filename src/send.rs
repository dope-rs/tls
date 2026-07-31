use std::iter::from_fn;

use dope_net::wire::buffered::{Buffer, Scratch};
use dope_net::wire::send::{Plain, Prepared, SendStorage, Sent, Storage, Vectored};

pub(crate) struct Cursor<'a, I>
where
    I: Iterator<Item = &'a [u8]>,
{
    source: I,
    current: &'a [u8],
    consumed: usize,
}

impl<'a, I> Cursor<'a, I>
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
        from_fn(move || {
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

    fn needs_buffer(&self) -> bool;
    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize;
    fn encrypt_vectored(&mut self, egress: &mut Buffer<Scratch>, vectored: &Vectored<'_>) -> usize;
    fn propagate_close(&mut self, egress: &mut Buffer<Scratch>) -> bool;
    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>);
    fn send_inflight(&mut self) -> &mut bool;
}

pub(crate) trait SendBuffer: SendStorage {
    fn buffer_mut(&mut self) -> Option<&mut Buffer<Scratch>>;
    fn try_buffer(&mut self) -> Option<&mut Buffer<Scratch>>;
    fn release_if_empty(&mut self) {}
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
        mut send: Storage<'b, P::Storage>,
        plain: Plain<'b>,
    ) -> Prepared<'b> {
        if plain.is_empty() && !self.protocol.needs_buffer() {
            return send.empty(0);
        }
        let Some(egress) = send.try_buffer() else {
            return send.empty(0);
        };
        let consumed = self.protocol.encrypt(egress, plain.as_slice());
        let close = self.protocol.propagate_close(egress);
        self.finish(send, consumed, close)
    }

    pub(crate) fn prepare_vectored<'b>(
        &mut self,
        mut send: Storage<'b, P::Storage>,
        vectored: Vectored<'b>,
    ) -> Prepared<'b> {
        if vectored.is_empty() && !self.protocol.needs_buffer() {
            return send.empty(0);
        }
        let Some(egress) = send.try_buffer() else {
            return send.empty(0);
        };
        let consumed = self.protocol.encrypt_vectored(egress, &vectored);
        let close = self.protocol.propagate_close(egress);
        self.finish(send, consumed, close)
    }

    pub(crate) fn after_send<'b>(
        &mut self,
        mut send: Storage<'b, P::Storage>,
        sent: Sent,
    ) -> Prepared<'b> {
        *self.protocol.send_inflight() = false;
        let Some(egress) = send.buffer_mut() else {
            return send.empty(0);
        };
        let Ok(prefix) = egress.try_consume_prefix(sent.get()) else {
            return send.empty(0).close_after();
        };
        prefix.commit();
        self.protocol.drain_to_egress(egress);
        let close = self.protocol.propagate_close(egress);
        self.finish(send, 0, close)
    }

    pub(crate) fn flush<'b>(&mut self, mut send: Storage<'b, P::Storage>) -> Prepared<'b> {
        if !self.protocol.needs_buffer() {
            return send.empty(0);
        }
        let Some(egress) = send.try_buffer() else {
            return send.empty(0);
        };
        self.protocol.encrypt(egress, &[]);
        let close = self.protocol.propagate_close(egress);
        self.finish(send, 0, close)
    }

    pub(crate) fn finish<'b>(
        &mut self,
        mut send: Storage<'b, P::Storage>,
        consumed: usize,
        close: bool,
    ) -> Prepared<'b> {
        send.release_if_empty();
        *self.protocol.send_inflight() = !send.as_slice().is_empty();
        let prepared = send.buffered(consumed);
        if close {
            prepared.close_after()
        } else {
            prepared
        }
    }
}
