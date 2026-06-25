use o3::buffer::Rolling;
use shin::record::{
    AEAD_TAG_LEN, ContentType, HEADER_LEN, MAX_CIPHERTEXT_BODY, MAX_PLAINTEXT_BODY, Opener,
    PlaintextRecord, RecordError, Sealer,
};
use shin::{Epoch, Event, KeyDirection};

use crate::staging::{TLS_STAGING_CAP, boxed_rolling};

// One record at a time; multi-record handshake flights reassemble in the
// separate `hs_reassembly`, so these only ever need room for one record.
const RECV_CAP: usize = TLS_STAGING_CAP;
const SEND_CAP: usize = TLS_STAGING_CAP;

const INCOMING_APP_CAP: usize = 1 << 20;
const HS_REASSEMBLY_CAP: usize = 1 << 18;

const ALERT_LEVEL_FATAL: u8 = 2;
const ALERT_RECORD_OVERFLOW: u8 = 22;

const HS_HEADER_LEN: usize = 4;

const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HS_PLAIN: u8 = 22;
const REC_AEAD: u8 = 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Handshaking,
    Established,
    Closed,
}

#[derive(Debug)]
pub enum Error {
    Other,
    Detail(shin::Error),
    Record(RecordError),
    UnexpectedRecord,
    NotEstablished,
    Io(std::io::Error),
    PlaintextAlert { level: u8, desc: u8 },
    Overflow,
    SendOverflow,
}

impl From<RecordError> for Error {
    fn from(e: RecordError) -> Self {
        Self::Record(e)
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Other, Self::Other)
            | (Self::UnexpectedRecord, Self::UnexpectedRecord)
            | (Self::NotEstablished, Self::NotEstablished)
            | (Self::Overflow, Self::Overflow)
            | (Self::SendOverflow, Self::SendOverflow) => true,
            (Self::Record(a), Self::Record(b)) => a == b,
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (
                Self::PlaintextAlert {
                    level: la,
                    desc: da,
                },
                Self::PlaintextAlert {
                    level: lb,
                    desc: db,
                },
            ) => la == lb && da == db,
            _ => false,
        }
    }
}

enum Side {
    Client(shin::client::Client),
    Server(shin::server::Server),
}

pub struct State {
    side: Side,
    phase: Phase,

    handshake_sealer: Option<Sealer>,
    handshake_opener: Option<Opener>,
    app_sealer: Option<Sealer>,
    app_opener: Option<Opener>,

    recv_buf: Box<Rolling<RECV_CAP>>,
    pending_send: Box<Rolling<SEND_CAP>>,
    incoming_app: Vec<u8>,
    hs_reassembly: Vec<u8>,

    handshake_keys_ready: bool,
}

impl State {
    pub fn new_client(config: shin::client::Config) -> Result<Self, Error> {
        let mut state = Self::empty(Side::Client(shin::client::Client::new(config)));
        let evs = match &mut state.side {
            Side::Client(c) => c.start().map_err(Error::Detail)?,
            _ => unreachable!(),
        };
        state.absorb_events(evs)?;
        Ok(state)
    }

    pub fn new_server(config: shin::server::Config) -> Self {
        Self::empty(Side::Server(shin::server::Server::new(config)))
    }

    fn seal_app(&mut self, ct: ContentType, data: &[u8]) -> Result<(), Error> {
        let sealer = self.app_sealer.as_mut().ok_or(Error::NotEstablished)?;
        let wire = sealer.seal(ct, data)?;
        if self.pending_send.spare_capacity() < wire.len() {
            return Err(Error::SendOverflow);
        }
        self.pending_send.push(&wire);
        Ok(())
    }

    fn seal_handshake(&mut self, data: &[u8]) -> Result<(), Error> {
        let sealer = self
            .handshake_sealer
            .as_mut()
            .ok_or(Error::UnexpectedRecord)?;
        let wire = sealer.seal(ContentType::Handshake, data)?;
        if self.pending_send.spare_capacity() < wire.len() {
            return Err(Error::SendOverflow);
        }
        self.pending_send.push(&wire);
        Ok(())
    }

    fn empty(side: Side) -> Self {
        crate::memstats::recv_borrow();
        crate::memstats::send_borrow();
        Self {
            side,
            phase: Phase::Handshaking,
            handshake_sealer: None,
            handshake_opener: None,
            app_sealer: None,
            app_opener: None,
            recv_buf: boxed_rolling(),
            pending_send: boxed_rolling(),
            incoming_app: Vec::new(),
            hs_reassembly: Vec::new(),
            handshake_keys_ready: false,
        }
    }

    pub fn read_tcp(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut rest = bytes;
        loop {
            let take = rest.len().min(self.recv_buf.spare_capacity());
            if take > 0 {
                self.recv_buf.push(&rest[..take]);
                rest = &rest[take..];
            }
            while self.consume_one_record()? {}
            if rest.is_empty() {
                return Ok(());
            }
            if take == 0 {
                return Err(Error::Record(RecordError::BodyTooLarge));
            }
        }
    }

    pub fn try_read_tcp(&mut self, bytes: &[u8]) -> bool {
        bytes.is_empty() || self.read_tcp(bytes).is_ok()
    }

    pub fn pending_send_slice(&self) -> &[u8] {
        self.pending_send.as_slice()
    }

    pub fn consume_pending_send(&mut self, n: usize) {
        self.pending_send.consume(n);
    }

    pub fn pull_send(&mut self) -> Vec<u8> {
        let v = self.pending_send.as_slice().to_vec();
        let n = v.len();
        self.pending_send.consume(n);
        v
    }

    pub fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, Error> {
        if !self.is_established() {
            return Err(Error::NotEstablished);
        }
        let mut consumed = 0;
        while consumed < plaintext.len() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plaintext.len());
            let need = HEADER_LEN + (end - consumed) + 1 + AEAD_TAG_LEN;
            if self.pending_send.spare_capacity() < need {
                break;
            }
            self.seal_app(ContentType::ApplicationData, &plaintext[consumed..end])?;
            consumed = end;
        }
        Ok(consumed)
    }

    pub fn send_key_update(&mut self, request_update: bool) -> Result<(), Error> {
        if !self.is_established() {
            return Err(Error::NotEstablished);
        }
        let evs = match &mut self.side {
            Side::Client(c) => c.send_key_update(request_update).map_err(Error::Detail)?,
            Side::Server(s) => s.send_key_update(request_update).map_err(Error::Detail)?,
        };
        self.absorb_events(evs)
    }

    pub fn send_close_notify(&mut self) -> Result<(), Error> {
        if self.is_closed() {
            return Ok(());
        }
        if !self.is_established() {
            return Err(Error::NotEstablished);
        }
        self.seal_app(ContentType::Alert, &[1, 0])?;
        self.phase = Phase::Closed;
        Ok(())
    }

    pub fn take_app(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.incoming_app)
    }

    pub fn pull_app(&mut self) -> Option<Vec<u8>> {
        if self.incoming_app.is_empty() {
            None
        } else {
            Some(self.take_app())
        }
    }

    pub fn is_handshaking(&self) -> bool {
        self.phase == Phase::Handshaking
    }

    pub fn is_established(&self) -> bool {
        self.phase == Phase::Established
    }

    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn selected_alpn(&self) -> Option<&[u8]> {
        match &self.side {
            Side::Client(c) => c.selected_alpn(),
            Side::Server(s) => s.selected_alpn(),
        }
    }

    fn consume_one_record(&mut self) -> Result<bool, Error> {
        if self.is_closed() {
            return Ok(false);
        }
        let view = self.recv_buf.as_slice();
        if view.len() < HEADER_LEN {
            return Ok(false);
        }
        let outer = view[0];
        let body_len = u16::from_be_bytes([view[3], view[4]]) as usize;
        if body_len > MAX_CIPHERTEXT_BODY {
            return Err(Error::Record(RecordError::BodyTooLarge));
        }
        let total = HEADER_LEN + body_len;
        if view.len() < total {
            return Ok(false);
        }

        match outer {
            REC_CCS => self.handle_ccs(total),
            REC_ALERT => self.handle_alert(total),
            REC_HS_PLAIN => self.handle_handshake_plaintext(total),
            REC_AEAD => self.handle_aead(total),
            _ => Err(Error::UnexpectedRecord),
        }
    }

    fn handle_ccs(&mut self, total: usize) -> Result<bool, Error> {
        self.recv_buf.consume(total);
        Ok(true)
    }

    fn handle_alert(&mut self, total: usize) -> Result<bool, Error> {
        let view = self.recv_buf.as_slice();
        let level = view.get(HEADER_LEN).copied().unwrap_or(0);
        let desc = view.get(HEADER_LEN + 1).copied().unwrap_or(0);
        self.recv_buf.consume(total);
        self.phase = Phase::Closed;
        Err(Error::PlaintextAlert { level, desc })
    }

    fn handle_handshake_plaintext(&mut self, total: usize) -> Result<bool, Error> {
        if total > HEADER_LEN + MAX_PLAINTEXT_BODY {
            return Err(Error::Record(RecordError::BodyTooLarge));
        }
        let view = self.recv_buf.as_slice();
        let (rec, consumed) =
            PlaintextRecord::parse(&view[..total])?.ok_or(Error::UnexpectedRecord)?;
        let inner = rec.body.to_vec();
        self.recv_buf.consume(consumed);
        self.feed_shin(Epoch::Plaintext, &inner)?;
        Ok(true)
    }

    fn handle_aead(&mut self, total: usize) -> Result<bool, Error> {
        let opener = if self.is_handshaking() {
            self.handshake_opener.as_mut()
        } else {
            self.app_opener.as_mut().or(self.handshake_opener.as_mut())
        }
        .ok_or(Error::UnexpectedRecord)?;

        let view_mut = self.recv_buf.as_mut_slice();
        let (inner_type, range, consumed) = opener
            .open(&mut view_mut[..total])?
            .ok_or(Error::UnexpectedRecord)?;

        match inner_type {
            ContentType::ApplicationData => {
                if self.incoming_app.len() + range.len() > INCOMING_APP_CAP {
                    self.recv_buf.consume(consumed);
                    return self.fatal_overflow();
                }
                self.incoming_app.extend_from_slice(&view_mut[range]);
                self.recv_buf.consume(consumed);
            }
            ContentType::Handshake => {
                let inner = view_mut[range].to_vec();
                self.recv_buf.consume(consumed);
                let epoch = if self.is_handshaking() && self.handshake_keys_ready {
                    Epoch::Handshake
                } else {
                    Epoch::Application
                };
                if self.hs_reassembly.len() + inner.len() > HS_REASSEMBLY_CAP {
                    return self.fatal_overflow();
                }
                self.hs_reassembly.extend_from_slice(&inner);
                let complete = State::complete_handshake_prefix(&self.hs_reassembly);
                if complete > 0 {
                    let msgs: Vec<u8> = self.hs_reassembly.drain(..complete).collect();
                    self.feed_shin(epoch, &msgs)?;
                }
            }
            ContentType::Alert => {
                self.recv_buf.consume(consumed);
                self.phase = Phase::Closed;
            }
            ContentType::ChangeCipherSpec => {
                self.recv_buf.consume(consumed);
            }
        }
        Ok(true)
    }

    fn fatal_overflow(&mut self) -> Result<bool, Error> {
        if self.app_sealer.is_some() {
            let _ = self.seal_app(
                ContentType::Alert,
                &[ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW],
            );
        }
        self.phase = Phase::Closed;
        Err(Error::Overflow)
    }

    fn complete_handshake_prefix(buf: &[u8]) -> usize {
        let mut off = 0;
        while buf.len() - off >= HS_HEADER_LEN {
            let len = u32::from_be_bytes([0, buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
            let msg_total = HS_HEADER_LEN + len;
            if buf.len() - off < msg_total {
                break;
            }
            off += msg_total;
        }
        off
    }

    fn feed_shin(&mut self, epoch: Epoch, data: &[u8]) -> Result<(), Error> {
        let evs = match &mut self.side {
            Side::Client(c) => c.read(epoch, data).map_err(Error::Detail)?,
            Side::Server(s) => s.read(epoch, data).map_err(Error::Detail)?,
        };
        self.absorb_events(evs)
    }

    fn absorb_events(&mut self, events: Vec<Event>) -> Result<(), Error> {
        for e in events {
            match e {
                Event::Send { epoch, data } => match epoch {
                    Epoch::Plaintext => {
                        let mut tmp: Vec<u8> = Vec::with_capacity(HEADER_LEN + data.len());
                        PlaintextRecord::encode(ContentType::Handshake, &data, &mut tmp)?;
                        if self.pending_send.spare_capacity() < tmp.len() {
                            return Err(Error::SendOverflow);
                        }
                        self.pending_send.push(&tmp);
                    }
                    Epoch::Handshake => self.seal_handshake(&data)?,
                    Epoch::Application => self.seal_app(ContentType::Handshake, &data)?,
                },
                Event::KeysReady {
                    epoch,
                    read_secret,
                    write_secret,
                } => match epoch {
                    Epoch::Handshake => {
                        self.handshake_opener = Some(Opener::from_secret(&read_secret));
                        self.handshake_sealer = Some(Sealer::from_secret(&write_secret));
                        self.handshake_keys_ready = true;
                    }
                    Epoch::Application => {
                        self.app_opener = Some(Opener::from_secret(&read_secret));
                        self.app_sealer = Some(Sealer::from_secret(&write_secret));
                    }
                    Epoch::Plaintext => {}
                },
                Event::KeyUpdate { direction, secret } => match direction {
                    KeyDirection::Read => {
                        self.app_opener = Some(Opener::from_secret(&secret));
                    }
                    KeyDirection::Write => {
                        self.app_sealer = Some(Sealer::from_secret(&secret));
                    }
                },
                Event::PeerExtension { .. } => {}
                Event::NewSessionTicket { .. } | Event::ResumptionSecret { .. } => {}
                Event::ZeroRttKeysReady { .. } => {}
                Event::Done => {
                    self.phase = Phase::Established;
                }
            }
        }
        Ok(())
    }
}

impl Drop for State {
    fn drop(&mut self) {
        crate::memstats::recv_release();
        crate::memstats::send_release();
    }
}

#[cfg(test)]
mod buffer_sizing_tests {
    use super::{RECV_CAP, SEND_CAP};
    use crate::staging::MAX_TLS_RECORD;

    #[test]
    fn recv_send_caps_are_right_sized() {
        const {
            assert!(RECV_CAP >= MAX_TLS_RECORD, "recv must fit one full record");
            assert!(SEND_CAP >= MAX_TLS_RECORD, "send must fit one full record");
            assert!(SEND_CAP <= 32 * 1024, "send must not be a bulk buffer");
            assert!(RECV_CAP <= 32 * 1024, "recv must not be a bulk buffer");
        }
    }
}

#[cfg(test)]
mod handshake_reassembly_tests {
    use super::State;

    fn msg(ty: u8, body_len: usize) -> Vec<u8> {
        let mut v = vec![ty];
        v.extend_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        v.extend(std::iter::repeat_n(0xAB, body_len));
        v
    }

    #[test]
    fn empty_buffer_has_no_complete_prefix() {
        assert_eq!(State::complete_handshake_prefix(&[]), 0);
    }

    #[test]
    fn header_only_is_incomplete() {
        assert_eq!(State::complete_handshake_prefix(&[11, 0, 0, 100]), 0);
    }

    #[test]
    fn single_whole_message() {
        let m = msg(11, 50);
        assert_eq!(State::complete_handshake_prefix(&m), m.len());
    }

    #[test]
    fn partial_body_is_retained() {
        let mut m = msg(11, 50);
        m.truncate(4 + 30);
        assert_eq!(State::complete_handshake_prefix(&m), 0);
    }

    #[test]
    fn whole_message_plus_partial_next() {
        let mut buf = msg(8, 10);
        let first = buf.len();
        buf.extend_from_slice(&msg(11, 200)[..4 + 100]);
        assert_eq!(State::complete_handshake_prefix(&buf), first);
    }

    #[test]
    fn multiple_whole_messages() {
        let mut buf = msg(8, 6);
        buf.extend(msg(11, 1400));
        buf.extend(msg(15, 260));
        buf.extend(msg(20, 36));
        assert_eq!(State::complete_handshake_prefix(&buf), buf.len());
    }
}

#[cfg(test)]
mod send_overflow_tests {
    use ring::rand::{SecureRandom, SystemRandom};
    use shin::sig::SigningKey;

    use super::{ContentType, Error, SEND_CAP, State};

    fn signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        SystemRandom::new().fill(&mut seed).unwrap();
        SigningKey::from_seed(&seed).unwrap()
    }

    fn pump(client: &mut State, server: &mut State) {
        for _ in 0..10 {
            let from_client = client.pull_send();
            let from_server = server.pull_send();
            let progressed = !from_client.is_empty() || !from_server.is_empty();
            if !from_client.is_empty() {
                server.read_tcp(&from_client).expect("server.read_tcp");
            }
            if !from_server.is_empty() {
                client.read_tcp(&from_server).expect("client.read_tcp");
            }
            if !progressed {
                break;
            }
        }
    }

    fn established_pair() -> (State, State) {
        let signing = signing_key();
        let server_pubkey = *signing.pubkey().unwrap();
        let mut server = State::new_server(shin::server::Config {
            source: shin::server::CertSource::RawPublicKey {
                signing_key: signing,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            ticket_secret: None,
            accept_early_data: false,
        });
        let mut client = State::new_client(shin::client::Config {
            verifier: shin::client::Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols: Vec::new(),
            resumption: None,
            enable_early_data: false,
        })
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_established() && server.is_established());
        (client, server)
    }

    // A near-full `pending_send` must make the next seal return Err(SendOverflow)
    // instead of panicking inside `Rolling::push`'s overflow assert.
    #[test]
    fn seal_app_returns_err_when_pending_send_nearly_full() {
        let (mut client, _server) = established_pair();

        // Fill pending_send so that only a handful of bytes remain free, far
        // less than a sealed application record needs.
        client
            .pending_send
            .consume(client.pending_send.as_slice().len());
        let chunk = [0u8; 4096];
        while client.pending_send.spare_capacity() > 8 {
            let take = chunk.len().min(client.pending_send.spare_capacity());
            client.pending_send.push(&chunk[..take]);
        }
        assert!(client.pending_send.spare_capacity() <= 8);
        assert!(client.pending_send.spare_capacity() < SEND_CAP);

        // This would overflow the 64 KiB buffer; old code panics in push().
        let err = client
            .seal_app(ContentType::ApplicationData, b"hello world")
            .unwrap_err();
        assert_eq!(err, Error::SendOverflow);

        // The same guard protects the handshake-seal response path.
        let err = client.seal_handshake(b"hello world").unwrap_err();
        assert_eq!(err, Error::SendOverflow);
    }
}
