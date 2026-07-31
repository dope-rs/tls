use dope_net::wire::buffered::{Buffer, Scratch};
use dope_net::wire::send::Vectored;
use shin::wire::record::MAX_PLAINTEXT_BODY;

use crate::send::Cursor;
use crate::staging::TLS13_RECORD_OVERHEAD;
use crate::state::State;
use crate::state::sessions::Session;
use crate::state::status::PeerClose;

use super::{Role, TlsConnection};

pub(super) struct Egress<'a, 'd, R: Role> {
    wire: &'a mut TlsConnection<'d, R>,
}

impl<'a, 'd, R: Role> Egress<'a, 'd, R> {
    pub(super) fn new(wire: &'a mut TlsConnection<'d, R>) -> Self {
        Self { wire }
    }

    pub(super) fn encrypt(&mut self, output: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        if self.wire.send_inflight {
            return 0;
        }
        self.drain(output);
        if !self.established() {
            return 0;
        }
        let mut consumed = 0;
        while consumed < plain.len() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plain.len());
            if !Self::record_fits(output, end - consumed) {
                break;
            }
            let count = self.seal_record(output, &plain[consumed..end]);
            if count == 0 {
                break;
            }
            consumed += count;
        }
        consumed
    }

    pub(super) fn encrypt_vectored(
        &mut self,
        output: &mut Buffer<Scratch>,
        vectored: &Vectored<'_>,
    ) -> usize {
        if self.wire.send_inflight {
            return 0;
        }
        self.drain(output);
        if !self.established() {
            return 0;
        }
        let total = vectored.bytes();
        let mut cursor = Cursor::new(vectored.iter());
        let mut consumed = 0;
        while consumed < total {
            let record_len = (total - consumed).min(MAX_PLAINTEXT_BODY);
            if !Self::record_fits(output, record_len) {
                break;
            }
            let tls = &mut self.wire.state.tls;
            match tls.write_app_parts_into(output, record_len, cursor.take(record_len)) {
                Ok(0) => return consumed,
                Ok(count) => consumed += count,
                Err(_) => {
                    self.wire.state.close = true;
                    return consumed;
                }
            }
            self.drain(output);
        }
        debug_assert_eq!(cursor.consumed(), consumed);
        consumed
    }

    pub(super) fn drain(&mut self, output: &mut Buffer<Scratch>) {
        if self.wire.send_inflight {
            return;
        }
        if !Self::drain_tls(&mut self.wire.state.tls, output) {
            self.wire.state.close = true;
        }
    }

    pub(super) fn propagate_close(&self) -> bool {
        self.wire.state.close || self.wire.peer_close() == PeerClose::CloseNotify
    }

    pub(super) fn seal_close_notify(&mut self, output: &mut Buffer<Scratch>) {
        if self.wire.state.close || self.wire.state.close_notify_sent {
            return;
        }
        let tls = &mut self.wire.state.tls;
        let sealed = tls.can_close_notify() && tls.send_close_notify().is_ok();
        if sealed {
            self.wire.state.close_notify_sent = true;
            self.drain(output);
        }
    }

    fn established(&self) -> bool {
        self.wire.state.tls.is_established()
    }

    fn record_fits(output: &Buffer<Scratch>, plaintext_len: usize) -> bool {
        output.spare_capacity() >= plaintext_len + TLS13_RECORD_OVERHEAD
    }

    fn seal_record(&mut self, output: &mut Buffer<Scratch>, chunk: &[u8]) -> usize {
        let tls = &mut self.wire.state.tls;
        let consumed = match tls.write_app_into(output, chunk) {
            Ok(count) => count,
            Err(_) => {
                self.wire.state.close = true;
                return 0;
            }
        };
        self.drain(output);
        consumed
    }

    fn drain_tls<S: Session>(tls: &mut State<S>, output: &mut Buffer<Scratch>) -> bool {
        let spare = output.spare_capacity();
        if spare == 0 {
            return true;
        }
        let pending = tls.pending_send_slice();
        let count = pending.len().min(spare);
        if count > 0
            && output.try_extend_from_slice(&pending[..count]).is_ok()
            && tls.consume_pending_send(count).is_err()
        {
            return false;
        }
        true
    }
}
