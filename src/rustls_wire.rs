use std::io::{self, Read, Write};
use std::slice;
use std::sync::Arc;

use dope::Driver;
use dope::runtime::token::Token;
use dope::transport::link::Core;
use dope::wire::{Reclaim, RecvChunk, Vectored, Wire};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use shin::record::MAX_PLAINTEXT_BODY;

use crate::pool::Pooled;
use crate::staging::MAX_TLS_RECORD;

const PENDING_APP_CAP: usize = 1 << 20;
/// Hard cap on the egress overflow `tail`. Ciphertext production is gated on
/// available egress room (see `egress_has_record_room`), so the tail should only
/// ever hold the remainder of a single record; this cap is a defensive bound so
/// a peer that stops reading can never drive `tail` to unbounded growth.
const TAIL_CAP: usize = 1 << 20;
/// Hard cap on buffered inbound ciphertext that rustls could not accept yet
/// because its received-plaintext buffer was full (backpressure, not an error).
const PENDING_RECV_CAP: usize = 1 << 20;

/// rustls-backed connection endpoint configuration carried in `InitConfig`.
///
/// Mirrors the shin `Endpoint` enum: it selects which kind of TLS connection a
/// freshly-`new`'d [`RustTls`] should construct.
#[derive(Clone, Default)]
pub enum RustTlsEndpoint {
    /// No TLS configured. Constructing a [`RustTls`] from this immediately
    /// flags the connection for close.
    #[default]
    None,
    /// Server side, using the shared [`ServerConfig`].
    Server(Arc<ServerConfig>),
    /// Client side, using the shared [`ClientConfig`] and target server name.
    Client {
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    },
}

enum Conn {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl Conn {
    fn read_tls(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        match self {
            Conn::Server(c) => c.read_tls(rd),
            Conn::Client(c) => c.read_tls(rd),
        }
    }

    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            Conn::Server(c) => c.process_new_packets(),
            Conn::Client(c) => c.process_new_packets(),
        }
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> std::io::Result<usize> {
        match self {
            Conn::Server(c) => c.write_tls(wr),
            Conn::Client(c) => c.write_tls(wr),
        }
    }

    fn wants_write(&self) -> bool {
        match self {
            Conn::Server(c) => c.wants_write(),
            Conn::Client(c) => c.wants_write(),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Conn::Server(c) => c.is_handshaking(),
            Conn::Client(c) => c.is_handshaking(),
        }
    }

    fn writer_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Server(c) => c.writer().write(buf),
            Conn::Client(c) => c.writer().write(buf),
        }
    }

    fn reader_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Server(c) => c.reader().read(buf),
            Conn::Client(c) => c.reader().read(buf),
        }
    }

    fn send_close_notify(&mut self) {
        match self {
            Conn::Server(c) => c.send_close_notify(),
            Conn::Client(c) => c.send_close_notify(),
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Conn::Server(c) => c.alpn_protocol(),
            Conn::Client(c) => c.alpn_protocol(),
        }
    }
}

struct ConnState {
    conn: Option<Conn>,
    pending_app: Vec<u8>,
    /// Inbound ciphertext rustls could not accept yet because its
    /// received-plaintext buffer was full. Re-fed on the next `process_recv`.
    pending_recv: Vec<u8>,
    close: bool,
}

impl ConnState {
    fn empty() -> Self {
        Self {
            conn: None,
            pending_app: Vec::new(),
            pending_recv: Vec::new(),
            close: false,
        }
    }
}

/// A rustls-backed [`Wire`] implementation.
///
/// Structurally mirrors the shin `Tls` wire: ciphertext destined for the socket
/// is staged in `egress` (a fixed [`Rolling`] buffer) plus an overflow `tail`,
/// and the single in-flight send is owned and re-driven by this type, which is
/// why [`Wire::RECLAIM`] is [`Reclaim::OnSubmit`].
pub struct RustTls {
    state: ConnState,
    /// Decrypted application plaintext, surfaced via `process_recv` for the
    /// `RustTlsEndpoint::None` path (kept for symmetry with the shin wire).
    ingress: Vec<u8>,
    egress: Pooled,
    /// Ciphertext that did not fit into `egress` on the last drain. Flushed back
    /// into `egress` (front of the queue) before pulling new ciphertext.
    tail: Vec<u8>,
    // True while a send referencing egress is in flight; egress must not move.
    send_inflight: bool,
}

impl RustTls {
    fn is_established(&self) -> bool {
        self.state
            .conn
            .as_ref()
            .is_some_and(|c| !c.is_handshaking())
    }

    /// Feed inbound ciphertext into rustls, run the state machine, and collect
    /// any decrypted application plaintext into `out`.
    ///
    /// Inbound ciphertext is the concatenation of any previously-buffered
    /// `pending_recv` (ciphertext rustls could not accept earlier due to
    /// backpressure) followed by `wire_in`. Plaintext is drained from rustls'
    /// reader as we go so its received-plaintext buffer does not back up; if it
    /// fills anyway (`read_tls` reporting buffer-full), that is treated as
    /// backpressure — we stop, buffer the unconsumed remainder, and never set
    /// `close`. Only genuine protocol errors flag the connection for close.
    fn ingress_decrypt(&mut self, wire_in: &[u8], out: &mut Vec<u8>) {
        if self.state.conn.is_none() {
            self.ingress.extend_from_slice(wire_in);
            return;
        }

        // Build the cursor over [pending_recv .. wire_in]. Avoid copying when
        // there is no carried-over ciphertext.
        let pending = std::mem::take(&mut self.state.pending_recv);
        let combined: Vec<u8>;
        let mut cursor: &[u8] = if pending.is_empty() {
            wire_in
        } else {
            combined = {
                let mut v = pending;
                v.extend_from_slice(wire_in);
                v
            };
            &combined
        };

        while !cursor.is_empty() {
            let conn = match self.state.conn.as_mut() {
                Some(c) => c,
                None => break,
            };
            match conn.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Other => {
                    // buffer-full: drain to free room and retry; stash only if no progress.
                    let before = out.len();
                    self.drain_reader(out);
                    if self.state.close {
                        return;
                    }
                    if out.len() == before {
                        self.buffer_pending_recv(cursor);
                        return;
                    }
                    continue;
                }
                Err(_) => {
                    self.state.close = true;
                    return;
                }
            }
            match self.state.conn.as_mut() {
                Some(conn) => match conn.process_new_packets() {
                    Ok(io) => {
                        if io.peer_has_closed() {
                            self.state.close = true;
                        }
                    }
                    Err(_) => {
                        self.state.close = true;
                        return;
                    }
                },
                None => break,
            }
            // Relieve received-plaintext pressure as we feed more ciphertext.
            self.drain_reader(out);
        }
    }

    /// Buffer inbound ciphertext that rustls could not accept yet. Bounded by
    /// `PENDING_RECV_CAP`; exceeding it flags the connection for close.
    fn buffer_pending_recv(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.state.pending_recv.len() + bytes.len() > PENDING_RECV_CAP {
            self.state.close = true;
            return;
        }
        self.state.pending_recv.extend_from_slice(bytes);
    }

    /// Move ciphertext rustls wants to send into `egress` (and `tail` overflow).
    ///
    /// No socket I/O happens here; that is deferred to `submit_wire_buf`.
    fn drain_to_egress(&mut self) {
        if self.send_inflight {
            return;
        }
        // First, flush any carried-over tail into egress.
        self.flush_tail();
        let mut scratch: Vec<u8> = Vec::new();
        {
            let Some(conn) = self.state.conn.as_mut() else {
                return;
            };
            while conn.wants_write() {
                match conn.write_tls(&mut scratch) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => {
                        self.state.close = true;
                        break;
                    }
                }
            }
        }
        if !scratch.is_empty() {
            self.stage_ciphertext(&scratch);
        }
    }

    /// Push as much of `bytes` into `egress` as fits, carrying the rest in `tail`.
    ///
    /// Ciphertext production is gated on egress room (see `egress_has_record_room`)
    /// so in steady state `tail` only ever holds the remainder of a single
    /// record. `TAIL_CAP` is a defensive hard bound: if a peer stops reading and
    /// the tail would exceed it, the connection is flagged for close rather than
    /// allowed to grow without bound.
    fn stage_ciphertext(&mut self, bytes: &[u8]) {
        if !self.tail.is_empty() {
            // Preserve ordering: anything already queued in tail comes first.
            self.push_tail(bytes);
            return;
        }
        let spare = self.egress.spare_capacity();
        let n = spare.min(bytes.len());
        if n > 0 {
            self.egress.push(&bytes[..n]);
        }
        if n < bytes.len() {
            self.push_tail(&bytes[n..]);
        }
    }

    /// Append to `tail`, enforcing the `TAIL_CAP` hard bound.
    fn push_tail(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.tail.len() + bytes.len() > TAIL_CAP {
            self.state.close = true;
            return;
        }
        self.tail.extend_from_slice(bytes);
    }

    /// Move buffered `tail` ciphertext into `egress` as room becomes available.
    fn flush_tail(&mut self) {
        if self.send_inflight || self.tail.is_empty() {
            return;
        }
        let spare = self.egress.spare_capacity();
        if spare == 0 {
            return;
        }
        let n = spare.min(self.tail.len());
        self.egress.push(&self.tail[..n]);
        self.tail.drain(..n);
    }

    /// True when `egress` has room for at least one full record of ciphertext.
    ///
    /// Production is gated on this so freshly-sealed ciphertext lands in `egress`
    /// (or, at worst, a single record's remainder in `tail`) and the caller is
    /// throttled via a short `consumed` count instead of the tail growing
    /// without bound. Mirrors the shin wire's `egress_has_record_room`.
    fn egress_has_record_room(&self) -> bool {
        self.tail.is_empty() && self.egress.spare_capacity() >= MAX_TLS_RECORD
    }

    /// Encrypt `plain`, buffering it while still handshaking.
    ///
    /// Returns the number of plaintext bytes consumed. Production is gated on
    /// available egress room, so when the peer is not draining the socket this
    /// returns a SHORT count (possibly 0) and the caller throttles instead of
    /// rustls' writer buffering unbounded ciphertext.
    fn encrypt(&mut self, plain: &[u8]) -> usize {
        if self.state.conn.is_none() {
            return self.buffer_pending(plain);
        }
        // If the handshake just finished, push any buffered app data first.
        self.maybe_flush_pending_app();
        self.drain_to_egress();
        if !self.is_established() {
            return self.buffer_pending(plain);
        }
        if !self.state.pending_app.is_empty() {
            // Could not fully flush buffered data yet; keep ordering.
            return self.buffer_pending(plain);
        }
        if plain.is_empty() {
            return 0;
        }
        let mut consumed = 0;
        while consumed < plain.len() && self.egress_has_record_room() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plain.len());
            let n = match self.state.conn.as_mut() {
                Some(conn) => match conn.writer_write(&plain[consumed..end]) {
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
            self.drain_to_egress();
        }
        consumed
    }

    fn buffer_pending(&mut self, plain: &[u8]) -> usize {
        if self.state.pending_app.len() + plain.len() > PENDING_APP_CAP {
            self.state.close = true;
            return 0;
        }
        if !plain.is_empty() {
            self.state.pending_app.extend_from_slice(plain);
        }
        plain.len()
    }

    fn maybe_flush_pending_app(&mut self) {
        if !self.is_established() || self.state.pending_app.is_empty() {
            return;
        }
        // Feed buffered app data a record at a time, gated on egress room so the
        // tail stays bounded. Whatever does not fit stays in `pending_app`.
        let mut off = 0;
        while off < self.state.pending_app.len() && self.egress_has_record_room() {
            let end = (off + MAX_PLAINTEXT_BODY).min(self.state.pending_app.len());
            let n = match self.state.conn.as_mut() {
                Some(conn) => match conn.writer_write(&self.state.pending_app[off..end]) {
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
            off += n;
            self.drain_to_egress();
        }
        self.state.pending_app.drain(..off);
    }

    /// Pull all currently-available decrypted plaintext out of rustls.
    fn take_app(&mut self) -> Vec<u8> {
        if self.state.conn.is_none() {
            return std::mem::take(&mut self.ingress);
        }
        let mut out: Vec<u8> = Vec::new();
        self.drain_reader(&mut out);
        out
    }

    /// Drain all currently-available decrypted plaintext from rustls' reader
    /// into `out`. A clean EOF (peer closed its write side) flags the
    /// connection for close.
    fn drain_reader(&mut self, out: &mut Vec<u8>) {
        let Some(conn) = self.state.conn.as_mut() else {
            return;
        };
        let mut buf = [0u8; 8192];
        loop {
            match conn.reader_read(&mut buf) {
                Ok(0) => {
                    // Clean EOF: peer closed the read side.
                    self.state.close = true;
                    break;
                }
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.state.close = true;
                    break;
                }
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

    fn propagate_close(&mut self, core: &mut Core, ud: Token, driver: &mut Driver) {
        if self.state.close {
            // Best-effort close_notify before tearing down.
            if let Some(conn) = self.state.conn.as_mut()
                && !conn.is_handshaking()
            {
                conn.send_close_notify();
            }
            self.drain_to_egress();
            // Make a real attempt to put the freshly-staged close_notify (and any
            // other pending ciphertext) on the wire before scheduling close, so a
            // clean shutdown is not abandoned unsent. Respects the one-send
            // in-flight guard inside `submit_wire_buf`.
            self.submit_wire_buf(core, ud, driver);
            core.set_close_after();
        }
    }

    /// Negotiated ALPN protocol, if any. Exposed for parity with the shin wire's
    /// `selected_alpn`.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.state.conn.as_ref().and_then(Conn::alpn_protocol)
    }
}

impl Wire for RustTls {
    type InitConfig = RustTlsEndpoint;

    const RECLAIM: Reclaim = Reclaim::OnSubmit;

    fn new(cfg: &RustTlsEndpoint) -> Self {
        let mut s = ConnState::empty();
        let conn = match cfg {
            RustTlsEndpoint::Server(c) => ServerConnection::new(c.clone()).ok().map(Conn::Server),
            RustTlsEndpoint::Client {
                config,
                server_name,
            } => ClientConnection::new(config.clone(), server_name.clone())
                .ok()
                .map(Conn::Client),
            RustTlsEndpoint::None => None,
        };
        s.close = conn.is_none();
        s.conn = conn;
        // rustls owns its own recv/send buffers, so this backend pools only egress.
        let mut me = Self {
            state: s,
            ingress: Vec::new(),
            egress: Pooled::egress(),
            tail: Vec::new(),
            send_inflight: false,
        };
        // A client immediately produces a ClientHello; stage it.
        me.drain_to_egress();
        me
    }

    fn process_recv<'a>(&mut self, bytes: &'a [u8]) -> Option<RecvChunk<'a>> {
        let mut data = Vec::new();
        self.ingress_decrypt(bytes, &mut data);
        self.maybe_flush_pending_app();
        self.drain_to_egress();
        // Pick up any plaintext that became available after flushing/draining
        // (and the no-conn `ingress` passthrough path).
        let tail = self.take_app();
        if data.is_empty() {
            data = tail;
        } else {
            data.extend_from_slice(&tail);
        }
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
        self.propagate_close(core, ud, driver);
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
        self.propagate_close(core, ud, driver);
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
            self.propagate_close(core, ud, driver);
            return false;
        }
        self.submit_wire_buf(core, ud, driver);
        true
    }

    fn flush_pending(&mut self, core: &mut Core, ud: Token, driver: &mut Driver) {
        self.encrypt(&[]);
        self.submit_wire_buf(core, ud, driver);
        self.propagate_close(core, ud, driver);
    }
}
