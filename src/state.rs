use std::sync::Arc;

use shin::alert::{Alert, AlertDescription, AlertParseError};
use shin::record::{
    AEAD_TAG_LEN, CipherSuite, ContentType, HEADER_LEN, MAX_CIPHERTEXT_BODY, MAX_PLAINTEXT_BODY,
    Opener, PlaintextRecord, RecordError, Sealer,
};
use shin::{Epoch, Event, KeyDirection};

use crate::pool::Pooled;

const INCOMING_APP_CAP: usize = 1 << 20;
const HS_REASSEMBLY_CAP: usize = 1 << 18;

const HS_HEADER_LEN: usize = 4;
const INNER_CONTENT_TYPE_LEN: usize = 1;
const KEY_UPDATE_PAYLOAD_LEN: usize = 1;

const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HS_PLAIN: u8 = 22;
const REC_AEAD: u8 = 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Handshaking,
    Established,
    PeerClosed,
    Closed,
}

#[derive(Debug)]
pub enum Error {
    Detail(shin::Error),
    Record(RecordError),
    UnexpectedRecord,
    NotEstablished,
    Io(std::io::Error),
    PeerAlert(AlertDescription),
    MalformedAlert,
    Truncated,
    Overflow,
    SendOverflow,
    EarlyDataUnsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerClose {
    Open,
    CloseNotify,
    Fatal(AlertDescription),
    Truncated,
}

impl From<RecordError> for Error {
    fn from(e: RecordError) -> Self {
        Self::Record(e)
    }
}

fn to_send_error(e: RecordError) -> Error {
    match e {
        RecordError::BufferTooSmall => Error::SendOverflow,
        other => Error::Record(other),
    }
}

fn seal_into(
    pending: &mut Pooled,
    sealer: &mut Sealer,
    ct: ContentType,
    data: &[u8],
) -> Result<(), Error> {
    pending
        .try_fill(|spare| sealer.seal_into_slice(ct, data, spare))
        .map_err(to_send_error)
}

fn encode_plaintext(pending: &mut Pooled, ct: ContentType, data: &[u8]) -> Result<(), Error> {
    pending
        .try_fill(|spare| PlaintextRecord::encode_into_slice(ct, data, spare))
        .map_err(to_send_error)
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnexpectedRecord, Self::UnexpectedRecord)
            | (Self::NotEstablished, Self::NotEstablished)
            | (Self::Overflow, Self::Overflow)
            | (Self::SendOverflow, Self::SendOverflow)
            | (Self::EarlyDataUnsupported, Self::EarlyDataUnsupported)
            | (Self::MalformedAlert, Self::MalformedAlert)
            | (Self::Truncated, Self::Truncated) => true,
            (Self::Record(a), Self::Record(b)) => a == b,
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (Self::PeerAlert(a), Self::PeerAlert(b)) => a == b,
            _ => false,
        }
    }
}

/// Per-connection wall clock, milliseconds since the UNIX epoch.
///
/// ```
/// # use dope_tls::WallClock;
/// let prod = WallClock::System;
/// let test = WallClock::FixedMillis(1_700_000_000_000);
/// ```
#[derive(Debug, Clone, Copy)]
pub enum WallClock {
    System,
    FixedMillis(u64),
}

impl shin::Clock for WallClock {
    fn now_ms(&self) -> u64 {
        match self {
            WallClock::System => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            WallClock::FixedMillis(ms) => *ms,
        }
    }
}

trait ServerSession {
    fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, shin::Error>;
    fn send_key_update(&mut self, request_update: bool) -> Result<Vec<Event>, shin::Error>;
    fn selected_alpn(&self) -> Option<&[u8]>;
    fn negotiated_cipher_suite(&self) -> Option<CipherSuite>;
    fn note_application_data(&mut self);
}

impl<V: shin::server::ClientCertVerifier> ServerSession
    for shin::server::Server<WallClock, shin::server::NoGuard, V>
{
    fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, shin::Error> {
        shin::server::Server::read(self, epoch, data)
    }
    fn send_key_update(&mut self, request_update: bool) -> Result<Vec<Event>, shin::Error> {
        shin::server::Server::send_key_update(self, request_update)
    }
    fn selected_alpn(&self) -> Option<&[u8]> {
        shin::server::Server::selected_alpn(self)
    }
    fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        shin::server::Server::negotiated_cipher_suite(self)
    }
    fn note_application_data(&mut self) {
        shin::server::Server::note_application_data(self);
    }
}

struct ArcClientVerifier(Arc<dyn shin::server::ClientCertVerifier + Send + Sync>);

impl shin::server::ClientCertVerifier for ArcClientVerifier {
    fn verify(&self, identity: &shin::server::ClientIdentity<'_>) -> bool {
        self.0.verify(identity)
    }
}

enum Side {
    Client(Box<shin::client::Client<WallClock>>),
    Server(Box<dyn ServerSession>),
}

pub struct State {
    side: Side,
    phase: Phase,

    handshake_sealer: Option<Sealer>,
    handshake_opener: Option<Opener>,
    app_sealer: Option<Sealer>,
    app_opener: Option<Opener>,

    recv_buf: Pooled,
    pending_send: Pooled,
    incoming_app: Vec<u8>,
    hs_reassembly: Vec<u8>,

    handshake_keys_ready: bool,
    peer_close: PeerClose,
}

impl State {
    pub fn new_client(config: shin::client::Config) -> Result<Self, Error> {
        Self::new_client_with_clock(config, WallClock::System)
    }

    pub fn new_client_with_clock(
        config: shin::client::Config,
        clock: WallClock,
    ) -> Result<Self, Error> {
        Self::new_client_with(config, clock, |_| {})
    }

    pub fn new_client_with(
        config: shin::client::Config,
        clock: WallClock,
        configure: impl FnOnce(&mut shin::client::Client<WallClock>),
    ) -> Result<Self, Error> {
        config.validate().map_err(Error::Detail)?;
        let mut client = shin::client::Client::new(config, clock);
        configure(&mut client);
        let mut state = Self::empty(Side::Client(Box::new(client)));
        let evs = match &mut state.side {
            Side::Client(c) => c.start().map_err(Error::Detail)?,
            _ => unreachable!(),
        };
        state.absorb_events(evs)?;
        Ok(state)
    }

    pub fn new_client_mutual(
        config: shin::client::Config,
        cert: shin::client::ClientCertSource,
    ) -> Result<Self, Error> {
        Self::new_client_mutual_with_clock(config, WallClock::System, cert)
    }

    pub fn new_client_mutual_with_clock(
        config: shin::client::Config,
        clock: WallClock,
        cert: shin::client::ClientCertSource,
    ) -> Result<Self, Error> {
        Self::new_client_with(config, clock, move |c| c.set_client_cert(cert))
    }

    pub fn new_server(config: shin::server::Config) -> Self {
        Self::new_server_with_clock(config, WallClock::System)
    }

    pub fn new_server_with_clock(config: shin::server::Config, clock: WallClock) -> Self {
        Self::empty(Side::Server(Box::new(shin::server::Server::new(
            config, clock,
        ))))
    }

    pub fn new_server_mutual(
        config: shin::server::Config,
        auth: shin::server::ClientAuth,
        verifier: Arc<dyn shin::server::ClientCertVerifier + Send + Sync>,
    ) -> Self {
        Self::new_server_mutual_with_clock(config, WallClock::System, auth, verifier)
    }

    pub fn new_server_mutual_with_clock(
        config: shin::server::Config,
        clock: WallClock,
        auth: shin::server::ClientAuth,
        verifier: Arc<dyn shin::server::ClientCertVerifier + Send + Sync>,
    ) -> Self {
        let server = shin::server::Server::with_client_auth(
            config,
            clock,
            auth,
            ArcClientVerifier(verifier),
        );
        Self::empty(Side::Server(Box::new(server)))
    }

    fn seal_app(&mut self, ct: ContentType, data: &[u8]) -> Result<(), Error> {
        let sealer = self.app_sealer.as_mut().ok_or(Error::NotEstablished)?;
        seal_into(&mut self.pending_send, sealer, ct, data)
    }

    fn seal_handshake(&mut self, data: &[u8]) -> Result<(), Error> {
        let sealer = self
            .handshake_sealer
            .as_mut()
            .ok_or(Error::UnexpectedRecord)?;
        seal_into(&mut self.pending_send, sealer, ContentType::Handshake, data)
    }

    fn empty(side: Side) -> Self {
        Self {
            side,
            phase: Phase::Handshaking,
            handshake_sealer: None,
            handshake_opener: None,
            app_sealer: None,
            app_opener: None,
            recv_buf: Pooled::recv(),
            pending_send: Pooled::send(),
            incoming_app: Vec::new(),
            hs_reassembly: Vec::new(),
            handshake_keys_ready: false,
            peer_close: PeerClose::Open,
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
                self.recv_buf.release_if_empty();
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
        self.pending_send.release_if_empty();
    }

    pub fn pull_send(&mut self) -> Vec<u8> {
        let v = self.pending_send.as_slice().to_vec();
        let n = v.len();
        self.pending_send.consume(n);
        self.pending_send.release_if_empty();
        v
    }

    pub fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, Error> {
        if !self.is_established() {
            return Err(Error::NotEstablished);
        }
        let mut consumed = 0;
        while consumed < plaintext.len() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plaintext.len());
            let need = HEADER_LEN + (end - consumed) + INNER_CONTENT_TYPE_LEN + AEAD_TAG_LEN;
            if self.pending_send.spare_capacity() < need {
                break;
            }
            self.seal_app(ContentType::ApplicationData, &plaintext[consumed..end])?;
            consumed = end;
        }
        self.maybe_auto_key_update()?;
        Ok(consumed)
    }

    fn maybe_auto_key_update(&mut self) -> Result<(), Error> {
        let due = self
            .app_sealer
            .as_ref()
            .is_some_and(|s| s.needs_key_update());
        const KEY_UPDATE_RECORD_MAX: usize = HEADER_LEN
            + HS_HEADER_LEN
            + KEY_UPDATE_PAYLOAD_LEN
            + INNER_CONTENT_TYPE_LEN
            + AEAD_TAG_LEN;
        if due && !self.is_closed() && self.pending_send.spare_capacity() >= KEY_UPDATE_RECORD_MAX {
            self.send_key_update(false)?;
        }
        Ok(())
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
        self.seal_closing_alert(Alert::close_notify())
    }

    pub fn send_fatal_alert(&mut self, desc: AlertDescription) -> Result<(), Error> {
        self.seal_closing_alert(Alert::fatal(desc))
    }

    fn seal_closing_alert(&mut self, alert: Alert) -> Result<(), Error> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        if self.app_sealer.is_none() {
            return Err(Error::NotEstablished);
        }
        self.seal_app(ContentType::Alert, &alert.body())?;
        self.phase = Phase::Closed;
        Ok(())
    }

    pub fn can_close_notify(&self) -> bool {
        matches!(self.phase, Phase::Established | Phase::PeerClosed) && self.app_sealer.is_some()
    }

    pub fn peer_close(&self) -> PeerClose {
        self.peer_close
    }

    /// Errors with [`Error::Truncated`] on EOF before the peer's close_notify.
    pub fn on_peer_eof(&mut self) -> Result<(), Error> {
        if self.peer_close == PeerClose::Open {
            self.peer_close = PeerClose::Truncated;
            self.phase = Phase::Closed;
            return Err(Error::Truncated);
        }
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
        matches!(self.phase, Phase::PeerClosed | Phase::Closed)
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

    fn cipher_suite(&self) -> CipherSuite {
        let negotiated = match &self.side {
            Side::Client(c) => c.negotiated_cipher_suite(),
            Side::Server(s) => s.negotiated_cipher_suite(),
        };
        negotiated.unwrap_or(CipherSuite::Aes128GcmSha256)
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
        let parsed = Alert::parse(
            self.recv_buf
                .as_slice()
                .get(HEADER_LEN..total)
                .unwrap_or(&[]),
        );
        self.recv_buf.consume(total);
        self.classify_alert(parsed, false)
    }

    fn classify_alert(
        &mut self,
        parsed: Result<Alert, AlertParseError>,
        encrypted: bool,
    ) -> Result<bool, Error> {
        let alert = match parsed {
            Ok(a) => a,
            Err(_) => {
                self.phase = Phase::Closed;
                self.peer_close = PeerClose::Fatal(AlertDescription::DecodeError);
                return Err(Error::MalformedAlert);
            }
        };
        if encrypted && alert.description == AlertDescription::CloseNotify {
            self.peer_close = PeerClose::CloseNotify;
            self.phase = if self.app_sealer.is_some() {
                Phase::PeerClosed
            } else {
                Phase::Closed
            };
            Ok(false)
        } else {
            self.phase = Phase::Closed;
            self.peer_close = PeerClose::Fatal(alert.description);
            Err(Error::PeerAlert(alert.description))
        }
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
        let opened = opener.open(&mut view_mut[..total]);
        let (inner_type, range, consumed) = match opened {
            Ok(Some(v)) => v,
            Ok(None) => return Err(Error::UnexpectedRecord),
            Err(e) => {
                let desc = match e {
                    RecordError::UnexpectedChangeCipherSpec => AlertDescription::UnexpectedMessage,
                    _ => AlertDescription::BadRecordMac,
                };
                self.stage_fatal_alert(desc);
                self.phase = Phase::Closed;
                return Err(Error::Record(e));
            }
        };

        match inner_type {
            ContentType::ApplicationData => {
                if self.incoming_app.len() + range.len() > INCOMING_APP_CAP {
                    self.recv_buf.consume(consumed);
                    return self.fatal_overflow();
                }
                self.incoming_app.extend_from_slice(&view_mut[range]);
                self.recv_buf.consume(consumed);
                match &mut self.side {
                    Side::Client(c) => c.note_application_data(),
                    Side::Server(s) => s.note_application_data(),
                }
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
                let parsed = Alert::parse(&view_mut[range]);
                self.recv_buf.consume(consumed);
                return self.classify_alert(parsed, true);
            }
            ContentType::ChangeCipherSpec => {
                self.recv_buf.consume(consumed);
            }
        }
        Ok(true)
    }

    fn fatal_overflow(&mut self) -> Result<bool, Error> {
        self.stage_fatal_alert(AlertDescription::RecordOverflow);
        self.phase = Phase::Closed;
        Err(Error::Overflow)
    }

    fn stage_fatal_alert(&mut self, desc: AlertDescription) {
        let alert = Alert::fatal(desc);
        if self.app_sealer.is_some() {
            let _ = self.seal_app(ContentType::Alert, &alert.body());
        } else {
            let _ = encode_plaintext(&mut self.pending_send, ContentType::Alert, &alert.body());
        }
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
        let result = match &mut self.side {
            Side::Client(c) => c.read(epoch, data),
            Side::Server(s) => s.read(epoch, data),
        };
        let evs = match result {
            Ok(evs) => evs,
            Err(e) => {
                self.stage_fatal_alert(e.alert().description);
                self.phase = Phase::Closed;
                return Err(Error::Detail(e));
            }
        };
        self.absorb_events(evs)
    }

    fn absorb_events(&mut self, events: Vec<Event>) -> Result<(), Error> {
        for e in events {
            match e {
                Event::Send { epoch, data } => match epoch {
                    Epoch::Plaintext => {
                        encode_plaintext(&mut self.pending_send, ContentType::Handshake, &data)?
                    }
                    Epoch::Handshake => self.seal_handshake(&data)?,
                    Epoch::Application => self.seal_app(ContentType::Handshake, &data)?,
                    Epoch::EarlyData => return Err(Error::EarlyDataUnsupported),
                },
                Event::KeysReady {
                    epoch,
                    read_secret,
                    write_secret,
                } => {
                    let suite = self.cipher_suite();
                    match epoch {
                        Epoch::Handshake => {
                            self.handshake_opener =
                                Some(Opener::with_suite(read_secret.as_slice(), suite));
                            self.handshake_sealer =
                                Some(Sealer::with_suite(write_secret.as_slice(), suite));
                            self.handshake_keys_ready = true;
                        }
                        Epoch::Application => {
                            self.app_opener =
                                Some(Opener::with_suite(read_secret.as_slice(), suite));
                            self.app_sealer =
                                Some(Sealer::with_suite(write_secret.as_slice(), suite));
                        }
                        Epoch::Plaintext | Epoch::EarlyData => {}
                    }
                }
                Event::KeyUpdate { direction, secret } => {
                    let suite = self.cipher_suite();
                    match direction {
                        KeyDirection::Read => {
                            self.app_opener = Some(Opener::with_suite(secret.as_slice(), suite));
                        }
                        KeyDirection::Write => {
                            self.app_sealer = Some(Sealer::with_suite(secret.as_slice(), suite));
                        }
                    }
                }
                Event::PeerExtension { .. } => {}
                Event::NewSessionTicket { .. } | Event::ResumptionSecret { .. } => {}
                Event::ZeroRttKeysReady { .. }
                | Event::EarlyDataAccepted
                | Event::EarlyDataRejected => {}
                Event::Done => {
                    self.phase = Phase::Established;
                }
            }
        }
        Ok(())
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

    use super::{ContentType, Error, State};
    use crate::staging::TLS_STAGING_CAP;

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
            ticket_keys: None,
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

    #[test]
    fn seal_app_returns_err_when_pending_send_nearly_full() {
        let (mut client, _server) = established_pair();

        client
            .pending_send
            .consume(client.pending_send.as_slice().len());
        let chunk = [0u8; 4096];
        while client.pending_send.spare_capacity() > 8 {
            let take = chunk.len().min(client.pending_send.spare_capacity());
            client.pending_send.push(&chunk[..take]);
        }
        assert!(client.pending_send.spare_capacity() <= 8);
        assert!(client.pending_send.spare_capacity() < TLS_STAGING_CAP);

        let err = client
            .seal_app(ContentType::ApplicationData, b"hello world")
            .unwrap_err();
        assert_eq!(err, Error::SendOverflow);

        let err = client.seal_handshake(b"hello world").unwrap_err();
        assert_eq!(err, Error::SendOverflow);
    }
}
