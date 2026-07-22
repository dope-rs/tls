use std::{
    io::{self, Error, ErrorKind},
    rc::Rc,
};

use dope_net::wire::send::{Plain, Prepared, SendStorage, Storage, Vectored};
use dope_net::wire::{
    Reclaim, RuntimeLimits, Wire,
    buffered::{Buffer, Buffered, Scratch},
};
use dope_net::{Bytes, Leased};
use shin::{client, record::MAX_PLAINTEXT_BODY, server};

use crate::send::{SendProtocol, Sender};
use crate::staging::{TLS_STAGING_CAP, TLS13_RECORD_OVERHEAD};
use crate::{
    clock::WallClock,
    state::{State, buffer::Buffers, status::PeerClose},
};

struct ConnectionState {
    pub tls: Option<State>,
    pub close: bool,
    close_notify_sent: bool,
}

impl ConnectionState {
    fn empty() -> Self {
        Self {
            tls: None,
            close: false,
            close_notify_sent: false,
        }
    }
}

#[derive(Clone, Default)]
pub enum Endpoint {
    #[default]
    None,
    Server(Box<server::Config>),
    ServerMutual {
        config: Box<server::Config>,
        auth: server::ClientAuth,
        verifier: Rc<dyn server::ClientCertVerifier>,
    },
    Client(client::Config),
    ClientMutual {
        config: Box<client::Config>,
        cert: client::ClientCertSource,
    },
}

impl Endpoint {
    pub fn server_mutual(
        config: server::Config,
        auth: server::ClientAuth,
        verifier: Rc<dyn server::ClientCertVerifier>,
    ) -> Self {
        Self::ServerMutual {
            config: Box::new(config),
            auth,
            verifier,
        }
    }

    pub fn client_mutual(config: client::Config, cert: client::ClientCertSource) -> Self {
        Self::ClientMutual {
            config: Box::new(config),
            cert,
        }
    }
}

pub struct Tls {
    state: ConnectionState,
    send_inflight: bool,
}

pub struct SendState(pub(crate) Buffer<Scratch>);

unsafe impl SendStorage for SendState {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Tls {
    pub(crate) fn runtime_buffers(
        limits: RuntimeLimits,
        scratch_per_connection: usize,
    ) -> io::Result<Buffered> {
        Buffered::try_for_runtime(
            limits,
            scratch_per_connection,
            TLS_STAGING_CAP,
            MAX_PLAINTEXT_BODY,
        )
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))
    }

    fn ingress_decrypt(&mut self, wire_in: &[u8]) {
        match self.state.tls.as_mut() {
            None => {
                let _ = wire_in;
                self.state.close = true;
            }
            Some(tls) => {
                if !tls.try_read_tcp(wire_in) {
                    self.state.close = true;
                    return;
                }
                if tls.is_closed() && tls.peer_close() != PeerClose::CloseNotify {
                    self.state.close = true;
                }
            }
        }
    }

    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        if self.state.tls.is_none() || self.send_inflight {
            return 0;
        }
        self.drain_to_egress(egress);
        if !self.is_established() {
            return 0;
        }
        let mut consumed = 0;
        while consumed < plain.len() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plain.len());
            if !Self::egress_has_record_room(egress, end - consumed) {
                break;
            }
            let n = self.seal_record(egress, &plain[consumed..end]);
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

    fn egress_has_record_room(egress: &Buffer<Scratch>, plaintext_len: usize) -> bool {
        egress.spare_capacity() >= plaintext_len + TLS13_RECORD_OVERHEAD
    }

    fn seal_record(&mut self, egress: &mut Buffer<Scratch>, chunk: &[u8]) -> usize {
        let Some(tls) = self.state.tls.as_mut() else {
            return 0;
        };
        let consumed = match tls.write_app_into(egress, chunk) {
            Ok(n) => n,
            Err(_) => {
                self.state.close = true;
                return 0;
            }
        };
        self.drain_to_egress(egress);
        consumed
    }

    fn drain_tls_to_egress(tls: &mut State, egress: &mut Buffer<Scratch>) {
        let spare = egress.spare_capacity();
        if spare == 0 {
            return;
        }
        let pending = tls.pending_send_slice();
        let n = pending.len().min(spare);
        if n > 0 {
            if egress.try_extend_from_slice(&pending[..n]).is_err() {
                return;
            }
            tls.consume_pending_send(n);
        }
    }

    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>) {
        if self.send_inflight {
            return;
        }
        if let Some(tls) = self.state.tls.as_mut() {
            Self::drain_tls_to_egress(tls, egress);
        }
    }

    fn propagate_close(&mut self, _egress: &mut Buffer<Scratch>) -> bool {
        self.state.close || self.peer_close() == PeerClose::CloseNotify
    }

    pub fn peer_close(&self) -> PeerClose {
        self.state
            .tls
            .as_ref()
            .map_or(PeerClose::Open, State::peer_close)
    }

    fn seal_close_notify(&mut self, egress: &mut Buffer<Scratch>) {
        if self.state.close || self.state.close_notify_sent {
            return;
        }
        let sealed = match self.state.tls.as_mut() {
            Some(tls) if tls.can_close_notify() => tls.send_close_notify().is_ok(),
            _ => false,
        };
        if sealed {
            self.state.close_notify_sent = true;
            self.drain_to_egress(egress);
        }
    }
}

impl SendProtocol for Tls {
    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        self.encrypt(egress, plain)
    }

    fn propagate_close(&mut self, egress: &mut Buffer<Scratch>) -> bool {
        self.propagate_close(egress)
    }

    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>) {
        self.drain_to_egress(egress);
    }

    fn send_inflight(&mut self) -> &mut bool {
        &mut self.send_inflight
    }
}

impl Wire for Tls {
    type InitConfig = Endpoint;
    type RuntimeContext = Buffered;
    type Recv<'a> = Bytes<Leased>;
    type SendStorage = SendState;

    const RECLAIM: Reclaim = Reclaim::OnSubmit;

    fn holds_plain(&self, send: &Self::SendStorage) -> bool {
        !send.0.as_slice().is_empty()
    }

    fn runtime_context(limits: RuntimeLimits) -> io::Result<Buffered> {
        Self::runtime_buffers(limits, 3)
    }

    fn open(cfg: &Endpoint, runtime: &Buffered) -> Option<(Self, SendState)> {
        let send = SendState(runtime.try_acquire_scratch()?);
        let mut s = ConnectionState::empty();
        let tls = match cfg {
            Endpoint::Server(c) => State::new_server_with_buffers(
                (**c).clone(),
                WallClock::System,
                Buffers::try_runtime(runtime)?,
            )
            .ok(),
            Endpoint::ServerMutual {
                config,
                auth,
                verifier,
            } => State::new_server_mutual_with_buffers(
                (**config).clone(),
                WallClock::System,
                *auth,
                verifier.clone(),
                Buffers::try_runtime(runtime)?,
            )
            .ok(),
            Endpoint::Client(c) => State::new_client_with_buffers(
                c.clone(),
                WallClock::System,
                |_| {},
                Buffers::try_runtime(runtime)?,
            )
            .ok(),
            Endpoint::ClientMutual { config, cert } => State::new_client_with_buffers(
                (**config).clone(),
                WallClock::System,
                |client| client.set_client_cert(cert.clone()),
                Buffers::try_runtime(runtime)?,
            )
            .ok(),
            Endpoint::None => None,
        };
        s.close = tls.is_none();
        s.tls = tls;
        Some((
            Self {
                state: s,
                send_inflight: false,
            },
            send,
        ))
    }

    fn process_recv<'a>(&mut self, _runtime: &Buffered, bytes: &'a [u8]) -> Option<Self::Recv<'a>> {
        self.ingress_decrypt(bytes);
        self.state.tls.as_mut()?.pull_leased_app()
    }

    fn recv_eof(&mut self) {
        if let Some(tls) = self.state.tls.as_mut() {
            let _ = tls.peer_eof();
        }
        self.state.close = true;
    }

    fn prepare_send<'a>(
        &'a mut self,
        send: Storage<'a, Self::SendStorage>,
        plain: Plain<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.prepare(send, plain)
    }

    fn prepare_send_vectored<'a>(
        &'a mut self,
        send: Storage<'a, Self::SendStorage>,
        vectored: Vectored<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.prepare_vectored(send, vectored)
    }

    fn submit_failed(&mut self) {
        self.send_inflight = false;
    }

    fn after_send<'a>(
        &'a mut self,
        send: Storage<'a, Self::SendStorage>,
        written: usize,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.after_send(send, written)
    }

    fn flush_pending<'a>(&'a mut self, send: Storage<'a, Self::SendStorage>) -> Prepared<'a> {
        let mut sender = Sender::new(self);
        sender.flush(send)
    }

    fn graceful_close<'a>(&'a mut self, mut send: Storage<'a, Self::SendStorage>) -> Prepared<'a> {
        self.seal_close_notify(&mut send.0);
        let close_after = self.propagate_close(&mut send.0);
        let mut sender = Sender::new(self);
        sender.finish(send, 0, close_after)
    }
}

const _: () = assert!(
    core::mem::size_of::<Tls>() < crate::staging::MAX_TLS_RECORD,
    "inline Tls must not embed a record-sized staging array"
);
