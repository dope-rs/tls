use std::array::from_fn;
use std::io::{self, BufRead, Error, ErrorKind, IoSlice, Write};
use std::option::IntoIter;
use std::sync::Arc;

use dope_net::wire::Lease;
use dope_net::wire::send::{Plain, Prepared, Storage, Vectored};
use dope_net::wire::{
    ReadyOpen, Reclaim, RecvChunk, RuntimeLimits, Wire,
    buffered::{Buffer, Buffered, Recv, Scratch},
};
use dope_net::{Bytes, Leased, Retained};
use rustls::{
    ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection,
    pki_types::ServerName,
};

use crate::send::{Cursor, SendProtocol, Sender};

#[doc(hidden)]
pub mod components;

use components::{CiphertextWriter, ConnectionState, RustSendState};

/// Stack capacity for current vectored producers.
const INLINE_IOV: usize = 32;
/// TLS record header width.
const TLS_HEADER_LEN: usize = 5;
/// TLS plaintext fragment limit.
const TLS_MAX_PLAINTEXT: usize = 1 << 14;
/// TLS ciphertext body limit.
const TLS_MAX_CIPHERTEXT: usize = TLS_MAX_PLAINTEXT + 256;
/// Rustls scratch capacity.
const RUSTLS_STAGING_CAP: usize = TLS_HEADER_LEN + TLS_MAX_CIPHERTEXT + 8 * 1024;
/// Maximum TLS 1.2 AEAD expansion used by supported suites.
const MAX_RECORD_OVERHEAD: usize = TLS_HEADER_LEN + 8 + 16;

#[derive(Default)]
pub enum RustTlsEndpoint {
    #[default]
    None,
    Server(Arc<ServerConfig>),
    Client {
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    },
}

pub struct RustTlsRuntime {
    buffers: Buffered,
    endpoint: RustTlsEndpoint,
}

pub struct RustTls {
    state: ConnectionState,
    send_inflight: bool,
    max_plaintext: usize,
}

impl RustTls {
    fn runtime_buffers(limits: RuntimeLimits) -> io::Result<Buffered> {
        Buffered::try_for_runtime_with_scratch_extra(
            limits,
            1,
            0,
            RUSTLS_STAGING_CAP,
            TLS_MAX_CIPHERTEXT,
        )
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))
    }

    fn is_established(&self) -> bool {
        self.state
            .conn
            .as_ref()
            .is_some_and(|c| !c.is_handshaking())
    }

    fn ingress_decrypt(&mut self, wire_in: &[u8], out: &mut Buffer<Recv>) {
        if self.state.conn.is_none() {
            self.state.close = true;
            return;
        }

        let mut cursor = wire_in;

        while !cursor.is_empty() {
            let conn = match self.state.conn.as_mut() {
                Some(c) => c,
                None => break,
            };
            match conn.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Other => {
                    let before = out.len();
                    self.drain_reader(out);
                    if self.state.close {
                        return;
                    }
                    if out.len() == before {
                        self.state.close = true;
                        return;
                    }
                    continue;
                }
                Err(_) => {
                    self.state.close = true;
                    return;
                }
            }
            let readable = match self.state.conn.as_mut() {
                Some(conn) => match conn.process_new_packets() {
                    Ok(io) => {
                        if io.peer_has_closed() {
                            self.state.close = true;
                        }
                        io.plaintext_bytes_to_read()
                    }
                    Err(_) => {
                        self.state.close = true;
                        return;
                    }
                },
                None => break,
            };
            self.state.readable_plain = readable;
            self.drain_reader(out);
        }
    }

    fn drain_to_egress(&mut self, egress: &mut Buffer<Scratch>) {
        if self.send_inflight {
            return;
        }
        let mut writer = CiphertextWriter::new(egress);
        let Some(conn) = self.state.conn.as_mut() else {
            return;
        };
        while conn.wants_write() && writer.remaining() != 0 {
            match conn.write_tls(&mut writer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.state.close = true;
                    break;
                }
            }
        }
    }

    fn egress_has_record_room(egress: &Buffer<Scratch>, plaintext_len: usize) -> bool {
        egress.spare_capacity() >= plaintext_len + MAX_RECORD_OVERHEAD
    }

    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        if self.state.conn.is_none() {
            return 0;
        }
        self.drain_to_egress(egress);
        if !self.is_established() {
            return 0;
        }
        if plain.is_empty() {
            return 0;
        }
        let mut consumed = 0;
        while consumed < plain.len() {
            let end = (consumed + self.max_plaintext).min(plain.len());
            if !Self::egress_has_record_room(egress, end - consumed) {
                break;
            }
            let n = match self.state.conn.as_mut() {
                Some(conn) => match conn.writer().write(&plain[consumed..end]) {
                    Ok(n) => n,
                    Err(_) => {
                        self.state.close = true;
                        break;
                    }
                },
                None => break,
            };
            if n == 0 {
                break;
            }
            consumed += n;
            self.drain_to_egress(egress);
        }
        consumed
    }

    fn encrypt_vectored(&mut self, egress: &mut Buffer<Scratch>, vectored: &Vectored<'_>) -> usize {
        if self.state.conn.is_none() || self.send_inflight {
            return 0;
        }
        self.drain_to_egress(egress);
        if !self.is_established() {
            return 0;
        }
        let total = vectored.bytes();
        let mut cursor = Cursor::new(vectored.iter());
        let mut consumed = 0;
        while consumed < total {
            let record_len = (total - consumed).min(self.max_plaintext);
            if !Self::egress_has_record_room(egress, record_len) {
                break;
            }
            match self.write_parts(cursor.take(record_len)) {
                Ok(n) if n == record_len => consumed += n,
                Ok(_) | Err(_) => {
                    self.state.close = true;
                    return consumed;
                }
            }
            self.drain_to_egress(egress);
        }
        debug_assert_eq!(cursor.consumed(), consumed);
        consumed
    }

    fn write_parts<'a>(&mut self, mut parts: impl Iterator<Item = &'a [u8]>) -> io::Result<usize> {
        let mut inline = [&[][..]; INLINE_IOV];
        let mut len = 0;
        while let Some(part) = parts.next() {
            if part.is_empty() {
                continue;
            }
            if len == INLINE_IOV {
                let mut overflow = Vec::with_capacity(len + 1 + parts.size_hint().0);
                overflow.extend(inline.iter().map(|part| IoSlice::new(part)));
                overflow.push(IoSlice::new(part));
                overflow.extend(parts.map(IoSlice::new));
                return self.write_io_slices(&overflow);
            }
            inline[len] = part;
            len += 1;
        }
        match len {
            0 => Ok(0),
            1 => self.write_one(inline[0]),
            _ => {
                let slices: [IoSlice<'_>; INLINE_IOV] =
                    from_fn(|index| IoSlice::new(inline[index]));
                self.write_io_slices(&slices[..len])
            }
        }
    }

    fn write_one(&mut self, plaintext: &[u8]) -> io::Result<usize> {
        self.state
            .conn
            .as_mut()
            .ok_or_else(|| Error::from(ErrorKind::NotConnected))?
            .writer()
            .write(plaintext)
    }

    fn write_io_slices(&mut self, plaintext: &[IoSlice<'_>]) -> io::Result<usize> {
        self.state
            .conn
            .as_mut()
            .ok_or_else(|| Error::from(ErrorKind::NotConnected))?
            .writer()
            .write_vectored(plaintext)
    }

    fn plaintext_limit(max_fragment_size: Option<usize>) -> usize {
        max_fragment_size
            .map(|size| size.saturating_sub(TLS_HEADER_LEN))
            .unwrap_or(TLS_MAX_PLAINTEXT)
    }

    fn drain_reader(&mut self, out: &mut Buffer<Recv>) {
        let mut remaining = self.state.readable_plain;
        if remaining == 0 {
            return;
        }
        let Some(conn) = self.state.conn.as_mut() else {
            return;
        };
        if remaining > out.spare_capacity() {
            self.state.close = true;
            return;
        }
        let mut close = false;
        while remaining > 0 {
            let read = match conn.reader().into_first_chunk() {
                Ok([]) => {
                    close = true;
                    break;
                }
                Ok(chunk) => {
                    let read = remaining.min(chunk.len());
                    if out.try_extend_from_slice(&chunk[..read]).is_err() {
                        close = true;
                        break;
                    }
                    read
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    close = true;
                    break;
                }
            };
            conn.reader().consume(read);
            remaining -= read;
        }
        self.state.readable_plain = remaining;
        self.state.close |= close;
    }

    fn propagate_close(&mut self, egress: &mut Buffer<Scratch>) -> bool {
        if self.state.close {
            if !self.state.close_notify_sent
                && let Some(conn) = self.state.conn.as_mut()
                && !conn.is_handshaking()
            {
                conn.send_close_notify();
                self.state.close_notify_sent = true;
            }
            self.drain_to_egress(egress);
        }
        self.state.close
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.state
            .conn
            .as_ref()
            .and_then(|conn| conn.alpn_protocol())
    }
}

impl SendProtocol for RustTls {
    type Storage = RustSendState;

    fn needs_buffer(&self) -> bool {
        self.state.close
            || self
                .state
                .conn
                .as_ref()
                .is_some_and(|conn| conn.wants_write())
    }

    fn encrypt(&mut self, egress: &mut Buffer<Scratch>, plain: &[u8]) -> usize {
        self.encrypt(egress, plain)
    }

    fn encrypt_vectored(&mut self, egress: &mut Buffer<Scratch>, vectored: &Vectored<'_>) -> usize {
        self.encrypt_vectored(egress, vectored)
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

impl Wire for RustTls {
    type Connection<'d> = Self;
    type ConnectionStorage = ();
    type InitConfig<'d> = RustTlsEndpoint;
    type RuntimeContext<'d> = RustTlsRuntime;
    type Open<'a, 'd>
        = ReadyOpen<Self::Connection<'d>, Self::SendStorage>
    where
        'd: 'a;
    type OpenError = rustls::Error;
    type Recv<'a> = Bytes<Leased>;
    type RecvBatch<'a> = IntoIter<RecvChunk<'a, Self::Recv<'a>>>;
    type RetainedRecv<'d> = Bytes<Retained>;
    type SendStorage = RustSendState;

    const RECLAIM: Reclaim = Reclaim::OnSubmit;

    fn connection_storage(_: usize) -> io::Result<()> {
        Ok(())
    }

    fn holds_plain<'d>(wire: &Self::Connection<'d>, send: &Self::SendStorage) -> bool {
        !send.0.as_slice().is_empty()
            || wire
                .state
                .conn
                .as_ref()
                .is_some_and(|conn| conn.wants_write())
    }

    fn runtime_context<'d>(
        limits: RuntimeLimits,
        endpoint: Self::InitConfig<'d>,
    ) -> io::Result<Self::RuntimeContext<'d>>
    where
        Self: 'd,
    {
        Ok(RustTlsRuntime {
            buffers: Self::runtime_buffers(limits)?,
            endpoint,
        })
    }

    fn prepare_open<'a, 'd>(
        runtime: &'a mut Self::RuntimeContext<'d>,
    ) -> Result<Option<Self::Open<'a, 'd>>, rustls::Error>
    where
        'd: 'a,
    {
        let Some(send) = runtime.buffers.try_acquire_scratch() else {
            return Ok(None);
        };
        let send = RustSendState(send);
        let mut s = ConnectionState::empty();
        let (conn, max_plaintext) = match &runtime.endpoint {
            RustTlsEndpoint::Server(c) => (
                Some(Connection::Server(ServerConnection::new(c.clone())?)),
                Self::plaintext_limit(c.max_fragment_size),
            ),
            RustTlsEndpoint::Client {
                config,
                server_name,
            } => (
                Some(Connection::Client(ClientConnection::new(
                    config.clone(),
                    server_name.clone(),
                )?)),
                Self::plaintext_limit(config.max_fragment_size),
            ),
            RustTlsEndpoint::None => (None, TLS_MAX_PLAINTEXT),
        };
        s.close = conn.is_none();
        s.conn = conn;
        Ok(Some(ReadyOpen::new(
            Self {
                state: s,
                send_inflight: false,
                max_plaintext,
            },
            send,
        )))
    }

    fn process_recv<'a, 'd>(
        wire: &mut Self::Connection<'d>,
        runtime: &mut Self::RuntimeContext<'d>,
        bytes: &'a mut [u8],
    ) -> Self::RecvBatch<'a> {
        let Some(mut data) = runtime.buffers.try_acquire_recv() else {
            wire.state.close = true;
            return None.into_iter();
        };
        wire.ingress_decrypt(bytes, &mut data);
        if data.is_empty() {
            return None.into_iter();
        }
        Some(RecvChunk::Owned(data.freeze())).into_iter()
    }

    fn process_retained_recv<'a, 'd>(
        wire: &mut Self::Connection<'d>,
        runtime: &mut Self::RuntimeContext<'d>,
        bytes: Lease<'a>,
    ) -> Option<Self::RetainedRecv<'a>> {
        let Some(mut data) = runtime.buffers.try_acquire_recv() else {
            wire.state.close = true;
            return None;
        };
        wire.ingress_decrypt(bytes.as_slice(), &mut data);
        (!data.is_empty()).then(|| data.freeze().into_retained())
    }

    fn recv_eof<'d>(wire: &mut Self::Connection<'d>) {
        wire.state.close = true;
    }

    fn prepare_send<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
        plain: Plain<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.prepare(send, plain)
    }

    fn prepare_send_vectored<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
        vectored: Vectored<'a>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.prepare_vectored(send, vectored)
    }

    fn submit_failed<'d>(wire: &mut Self::Connection<'d>) {
        wire.send_inflight = false;
    }

    fn after_send<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
        sent: dope_net::wire::send::Sent,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.after_send(send, sent)
    }

    fn flush_pending<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        send: Storage<'a, Self::SendStorage>,
    ) -> Prepared<'a> {
        let mut sender = Sender::new(wire);
        sender.flush(send)
    }

    fn graceful_close<'a, 'd>(
        wire: &'a mut Self::Connection<'d>,
        mut send: Storage<'a, Self::SendStorage>,
    ) -> Prepared<'a> {
        wire.state.close = true;
        let close = wire.propagate_close(&mut send.0);
        let mut sender = Sender::new(wire);
        sender.finish(send, 0, close)
    }
}
