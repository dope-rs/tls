use std::io::{self, BufRead, Error, ErrorKind, IoSlice, Write};
use std::sync::Arc;

use dope_net::wire::send::{Plain, Prepared, Storage, Vectored};
use dope_net::wire::{
    Reclaim, RuntimeLimits, Wire,
    buffered::{Buffer, Buffered, Recv, Scratch},
};
use dope_net::{Bytes, Leased};
use rustls::{
    ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection,
    pki_types::ServerName,
};
use shin::record::MAX_PLAINTEXT_BODY;

use crate::send::{SendProtocol, Sender};
use crate::staging::TLS13_RECORD_OVERHEAD;
use crate::tls::{SendState, Tls};

#[derive(Clone, Default)]
pub enum RustTlsEndpoint {
    #[default]
    None,
    Server(Arc<ServerConfig>),
    Client {
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    },
}

struct ConnectionState {
    conn: Option<Connection>,
    readable_plain: usize,
    close: bool,
    close_notify_sent: bool,
}

struct CiphertextWriter<'a> {
    egress: &'a mut Buffer<Scratch>,
}

impl CiphertextWriter<'_> {
    fn remaining(&self) -> usize {
        self.egress.spare_capacity()
    }
}

impl Write for CiphertextWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let n = self.remaining().min(bytes.len());
        if n == 0 {
            Err(Error::from(ErrorKind::WouldBlock))
        } else {
            self.egress
                .try_extend_from_slice(&bytes[..n])
                .map_err(|_| Error::from(ErrorKind::WouldBlock))?;
            Ok(n)
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut written = 0;
        let mut has_bytes = false;
        for bytes in bufs {
            if bytes.is_empty() {
                continue;
            }
            has_bytes = true;
            let n = self.remaining().min(bytes.len());
            if n == 0 {
                break;
            }
            self.egress
                .try_extend_from_slice(&bytes[..n])
                .map_err(|_| Error::from(ErrorKind::WouldBlock))?;
            written += n;
            if n != bytes.len() {
                break;
            }
        }
        if written == 0 && has_bytes {
            Err(Error::from(ErrorKind::WouldBlock))
        } else {
            Ok(written)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ConnectionState {
    fn empty() -> Self {
        Self {
            conn: None,
            readable_plain: 0,
            close: false,
            close_notify_sent: false,
        }
    }
}

pub struct RustTls {
    state: ConnectionState,
    send_inflight: bool,
}

impl RustTls {
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
        let mut writer = CiphertextWriter { egress };
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
        egress.spare_capacity() >= plaintext_len + TLS13_RECORD_OVERHEAD
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
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plain.len());
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

impl Wire for RustTls {
    type InitConfig = RustTlsEndpoint;
    type RuntimeContext = Buffered;
    type Recv<'a> = Bytes<Leased>;
    type SendStorage = SendState;

    const RECLAIM: Reclaim = Reclaim::OnSubmit;

    fn holds_plain(&self, send: &Self::SendStorage) -> bool {
        !send.0.as_slice().is_empty()
            || self
                .state
                .conn
                .as_ref()
                .is_some_and(|conn| conn.wants_write())
    }

    fn runtime_context(limits: RuntimeLimits) -> io::Result<Buffered> {
        Tls::runtime_buffers(limits, 1)
    }

    fn open(cfg: &RustTlsEndpoint, runtime: &Buffered) -> Option<(Self, SendState)> {
        let send = SendState(runtime.try_acquire_scratch()?);
        let mut s = ConnectionState::empty();
        let conn = match cfg {
            RustTlsEndpoint::Server(c) => ServerConnection::new(c.clone())
                .ok()
                .map(Connection::Server),
            RustTlsEndpoint::Client {
                config,
                server_name,
            } => ClientConnection::new(config.clone(), server_name.clone())
                .ok()
                .map(Connection::Client),
            RustTlsEndpoint::None => None,
        };
        s.close = conn.is_none();
        s.conn = conn;
        Some((
            Self {
                state: s,
                send_inflight: false,
            },
            send,
        ))
    }

    fn process_recv<'a>(&mut self, runtime: &Buffered, bytes: &'a [u8]) -> Option<Self::Recv<'a>> {
        let Some(mut data) = runtime.try_acquire_recv() else {
            self.state.close = true;
            return None;
        };
        self.ingress_decrypt(bytes, &mut data);
        if data.is_empty() {
            return None;
        }
        Some(data.freeze())
    }

    fn recv_eof(&mut self) {
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
        self.state.close = true;
        let close = self.propagate_close(&mut send.0);
        let mut sender = Sender::new(self);
        sender.finish(send, 0, close)
    }
}
