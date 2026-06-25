use std::slice;

use dope::Driver;
use dope::runtime::token::Token;
use dope::transport::link::Core;
use dope::wire::{Reclaim, RecvChunk, Vectored, Wire};
use shin::record::MAX_PLAINTEXT_BODY;

use crate::pool::Pooled;
use crate::staging::MAX_TLS_RECORD;
use crate::state::State;

const PENDING_APP_CAP: usize = 1 << 20;
const INGRESS_CAP: usize = 1 << 20;

pub struct ConnState {
    pub tls: Option<State>,
    pub pending_app: Vec<u8>,
    pub close: bool,
}

impl ConnState {
    fn empty() -> Self {
        Self {
            tls: None,
            pending_app: Vec::new(),
            close: false,
        }
    }
}

#[derive(Clone, Default)]
pub enum Endpoint {
    #[default]
    None,
    Server(Box<shin::server::Config>),
    Client(shin::client::Config),
}

pub struct Tls {
    state: ConnState,
    ingress: Vec<u8>,
    egress: Pooled,
    // True while a send referencing egress is in flight; egress must not move.
    send_inflight: bool,
}

impl Tls {
    fn ingress_decrypt(&mut self, wire_in: &[u8]) {
        match self.state.tls.as_mut() {
            None => {
                if self.ingress.len() + wire_in.len() > INGRESS_CAP {
                    self.state.close = true;
                    return;
                }
                self.ingress.extend_from_slice(wire_in);
            }
            Some(tls) => {
                if !tls.try_read_tcp(wire_in) {
                    self.state.close = true;
                    return;
                }
                if tls.is_closed() {
                    self.state.close = true;
                }
            }
        }
    }

    fn encrypt(&mut self, plain: &[u8]) -> usize {
        if self.state.tls.is_none() {
            if self.state.pending_app.len() + plain.len() > PENDING_APP_CAP {
                self.state.close = true;
                return 0;
            }
            if !plain.is_empty() {
                self.state.pending_app.extend_from_slice(plain);
            }
            return plain.len();
        }
        self.drain_to_egress();
        if !self.is_established() {
            if self.state.pending_app.len() + plain.len() > PENDING_APP_CAP {
                self.state.close = true;
                return 0;
            }
            if !plain.is_empty() {
                self.state.pending_app.extend_from_slice(plain);
            }
            return plain.len();
        }
        self.flush_pending_app();
        if !self.state.pending_app.is_empty() {
            return 0;
        }
        let mut consumed = 0;
        while consumed < plain.len() && self.egress_has_record_room() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plain.len());
            let n = self.seal_record(&plain[consumed..end]);
            if n == 0 {
                break;
            }
            consumed += n;
        }
        consumed
    }

    fn is_established(&self) -> bool {
        self.state.tls.as_ref().is_some_and(State::is_established)
    }

    fn egress_has_record_room(&self) -> bool {
        self.egress.spare_capacity() >= MAX_TLS_RECORD
    }

    fn seal_record(&mut self, chunk: &[u8]) -> usize {
        let Some(tls) = self.state.tls.as_mut() else {
            return 0;
        };
        let consumed = match tls.write_app(chunk) {
            Ok(n) => n,
            Err(_) => {
                self.state.close = true;
                return 0;
            }
        };
        self.drain_to_egress();
        consumed
    }

    fn flush_pending_app(&mut self) {
        while !self.state.pending_app.is_empty() && self.egress_has_record_room() {
            let end = MAX_PLAINTEXT_BODY.min(self.state.pending_app.len());
            let chunk = self.state.pending_app[..end].to_vec();
            let n = self.seal_record(&chunk);
            if n == 0 {
                return;
            }
            self.state.pending_app.drain(..n);
        }
    }

    fn drain_to_egress(&mut self) {
        if self.send_inflight {
            return;
        }
        let spare = self.egress.spare_capacity();
        if spare == 0 {
            return;
        }
        if let Some(tls) = self.state.tls.as_mut() {
            let pending = tls.pending_send_slice();
            let n = pending.len().min(spare);
            if n > 0 {
                self.egress.push(&pending[..n]);
                tls.consume_pending_send(n);
            }
        }
    }

    fn submit_wire_buf(&mut self, core: &mut Core, ud: Token, driver: &mut Driver) {
        if core.is_send_inflight() {
            return;
        }
        let wire = self.egress.as_slice();
        if wire.is_empty() {
            return;
        }
        core.submit_single(ud, wire, driver);
        self.send_inflight = true;
    }

    fn propagate_close(&self, core: &mut Core) {
        if self.state.close {
            core.set_close_after();
        }
    }
}

impl Wire for Tls {
    type InitConfig = Endpoint;

    const RECLAIM: Reclaim = Reclaim::OnSubmit;

    fn new(cfg: &Endpoint) -> Self {
        let mut s = ConnState::empty();
        let tls = match cfg {
            Endpoint::Server(c) => Some(State::new_server((**c).clone())),
            Endpoint::Client(c) => State::new_client(c.clone()).ok(),
            Endpoint::None => None,
        };
        s.close = tls.is_none();
        s.tls = tls;
        Self {
            state: s,
            ingress: Vec::new(),
            egress: Pooled::egress(),
            send_inflight: false,
        }
    }

    fn process_recv<'a>(&mut self, bytes: &'a [u8]) -> Option<RecvChunk<'a>> {
        self.ingress_decrypt(bytes);
        if self.is_established() && !self.state.pending_app.is_empty() {
            self.flush_pending_app();
        }
        self.drain_to_egress();
        let data = match self.state.tls.as_mut() {
            Some(tls) => tls.take_app(),
            None => std::mem::take(&mut self.ingress),
        };
        if data.is_empty() {
            return None;
        }
        Some(RecvChunk::Owned(data))
    }

    fn submit_send(
        &mut self,
        core: &mut Core,
        plain: &[u8],
        ud: Token,
        driver: &mut Driver,
    ) -> usize {
        let consumed = self.encrypt(plain);
        self.submit_wire_buf(core, ud, driver);
        self.propagate_close(core);
        consumed
    }

    fn submit_send_vectored(
        &mut self,
        core: &mut Core,
        vectored: Vectored<'_>,
        ud: Token,
        driver: &mut Driver,
    ) -> usize {
        let mut consumed = 0;
        for iov in vectored.iovs {
            if iov.is_empty() {
                continue;
            }
            // SAFETY: `iov` references caller-owned memory valid for this call.
            let plain = unsafe { slice::from_raw_parts(iov.as_ptr(), iov.len()) };
            let c = self.encrypt(plain);
            consumed += c;
            if c < plain.len() {
                break;
            }
        }
        self.submit_wire_buf(core, ud, driver);
        self.propagate_close(core);
        consumed
    }

    fn after_send_cqe(
        &mut self,
        core: &mut Core,
        n: usize,
        ud: Token,
        driver: &mut Driver,
    ) -> bool {
        self.send_inflight = false;
        self.egress.consume(n);
        self.drain_to_egress();
        if self.egress.is_empty() {
            self.egress.release_if_empty();
            self.propagate_close(core);
            return false;
        }
        self.submit_wire_buf(core, ud, driver);
        true
    }

    fn flush_pending(&mut self, core: &mut Core, ud: Token, driver: &mut Driver) {
        self.encrypt(&[]);
        self.submit_wire_buf(core, ud, driver);
        self.propagate_close(core);
    }
}

#[cfg(test)]
mod buffer_sizing_tests {
    use ring::rand::{SecureRandom, SystemRandom};
    use shin::sig::SigningKey;

    use super::*;
    use crate::staging::TLS_STAGING_CAP;

    fn server_endpoint() -> Endpoint {
        let mut seed = [0u8; 32];
        SystemRandom::new().fill(&mut seed).unwrap();
        let signing = SigningKey::from_seed(&seed).unwrap();
        Endpoint::Server(Box::new(shin::server::Config {
            source: shin::server::CertSource::RawPublicKey {
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_secret: None,
            accept_early_data: false,
        }))
    }

    #[test]
    fn egress_is_right_sized_to_one_record() {
        const {
            assert!(
                TLS_STAGING_CAP >= MAX_TLS_RECORD,
                "egress must fit one full TLS record"
            );
            assert!(
                TLS_STAGING_CAP <= 32 * 1024,
                "egress must not be a 32/64 KiB bulk buffer"
            );
        }
    }

    #[test]
    fn ingress_is_lazy_not_preallocated() {
        let tls = Tls::new(&server_endpoint());
        assert_eq!(
            tls.ingress.capacity(),
            0,
            "ingress must be lazily allocated, not pre-sized"
        );
    }

    #[test]
    fn inline_tls_does_not_embed_staging_array() {
        const {
            assert!(
                core::mem::size_of::<Tls>() < MAX_TLS_RECORD,
                "inline Tls must not embed a record-sized staging array"
            );
        }
    }
}
