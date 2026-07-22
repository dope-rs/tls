use dope_net::wire::buffered::{Buffer, Scratch};
use dope_net::wire::send::{Plain, Prepared, Storage, Vectored};

use crate::tls::SendState;

pub(crate) trait SendProtocol {
    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize;
    fn propagate_close(&mut self, egress: &mut Buffer<Scratch>) -> bool;
    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>);
    fn send_inflight(&mut self) -> &mut bool;
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
        mut send: Storage<'b, SendState>,
        plain: Plain<'b>,
    ) -> Prepared<'b> {
        let consumed = self.protocol.encrypt(&mut send.0, plain.as_slice());
        let close = self.protocol.propagate_close(&mut send.0);
        self.finish(send, consumed, close)
    }

    pub(crate) fn prepare_vectored<'b>(
        &mut self,
        mut send: Storage<'b, SendState>,
        vectored: Vectored<'b>,
    ) -> Prepared<'b> {
        let mut consumed = 0;
        for plain in vectored.iter() {
            if plain.is_empty() {
                continue;
            }
            let current = self.protocol.encrypt(&mut send.0, plain);
            consumed += current;
            if current < plain.len() {
                break;
            }
        }
        let close = self.protocol.propagate_close(&mut send.0);
        self.finish(send, consumed, close)
    }

    pub(crate) fn after_send<'b>(
        &mut self,
        mut send: Storage<'b, SendState>,
        written: usize,
    ) -> Prepared<'b> {
        *self.protocol.send_inflight() = false;
        send.0.consume(written);
        self.protocol.drain_to_egress(&mut send.0);
        let close = self.protocol.propagate_close(&mut send.0);
        self.finish(send, 0, close)
    }

    pub(crate) fn flush<'b>(&mut self, mut send: Storage<'b, SendState>) -> Prepared<'b> {
        self.protocol.encrypt(&mut send.0, &[]);
        let close = self.protocol.propagate_close(&mut send.0);
        self.finish(send, 0, close)
    }

    pub(crate) fn finish<'b>(
        &mut self,
        send: Storage<'b, SendState>,
        consumed: usize,
        close: bool,
    ) -> Prepared<'b> {
        *self.protocol.send_inflight() = !send.0.is_empty();
        let prepared = send.buffered(consumed);
        if close {
            prepared.close_after()
        } else {
            prepared
        }
    }
}
