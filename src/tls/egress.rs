use dope::net::wire::send;
use o3::buffer::pool;
use shin::wire::{alert, record};

use crate::state::Internals as _;
use crate::state::api::capabilities::Status as _;
use crate::state::status;
use crate::tls::roles;
use crate::{staging, tls, transmissions};

pub(super) struct Egress<'a, 'd, R: roles::Protocol, const ID: u8> {
    wire: &'a mut tls::Connection<'d, R, ID>,
}

impl<'a, 'd, R: roles::Protocol, const ID: u8> Egress<'a, 'd, R, ID> {
    pub(super) fn new(wire: &'a mut tls::Connection<'d, R, ID>) -> Self {
        Self { wire }
    }

    pub(super) fn encrypt(&mut self, output: &mut pool::BorrowedCursor<'d>, plain: &[u8]) -> usize {
        if self.wire.send_inflight {
            return 0;
        }
        if !self.established() {
            return 0;
        }
        let mut consumed = 0;
        while consumed < plain.len() {
            let end = (consumed + record::MAX_PLAINTEXT_BODY).min(plain.len());
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
        output: &mut pool::BorrowedCursor<'d>,
        vectored: &send::Vectored<'_>,
    ) -> usize {
        if self.wire.send_inflight {
            return 0;
        }
        if !self.established() {
            return 0;
        }
        let total = vectored.bytes();
        let mut cursor = transmissions::VectoredCursor::new(vectored.iter());
        let mut consumed = 0;
        while consumed < total {
            let record_len = (total - consumed).min(record::MAX_PLAINTEXT_BODY);
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
        }
        debug_assert_eq!(cursor.consumed(), consumed);
        consumed
    }

    pub(super) fn propagate_close(&self) -> bool {
        !self.wire.state.tls.has_pending_control()
            && (self.wire.state.close
                || self.wire.state.tls.peer_close() == status::PeerClose::CloseNotify)
    }

    pub(super) fn seal_close_notify(&mut self, output: &mut pool::BorrowedCursor<'d>) {
        if self.wire.state.close || self.wire.state.close_notify_sent {
            return;
        }
        let tls = &mut self.wire.state.tls;
        let sealed = tls.can_close_notify()
            && tls
                .seal_closing_alert_into(output, alert::Alert::close_notify())
                .is_ok();
        if sealed {
            self.wire.state.close_notify_sent = true;
        }
    }

    fn established(&self) -> bool {
        self.wire.state.tls.is_established()
    }

    fn record_fits(output: &pool::BorrowedCursor<'_>, plaintext_len: usize) -> bool {
        output.spare_capacity() >= plaintext_len + staging::TLS13_RECORD_OVERHEAD
    }

    fn seal_record(&mut self, output: &mut pool::BorrowedCursor<'d>, chunk: &[u8]) -> usize {
        let tls = &mut self.wire.state.tls;
        match tls.write_app_into(output, chunk) {
            Ok(count) => count,
            Err(_) => {
                self.wire.state.close = true;
                0
            }
        }
    }
}
