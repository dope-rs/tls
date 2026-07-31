use dope_net::wire::buffered::{Buffer, FillError, Scratch};
use shin::connection::{self, DriveError, Epoch, Event, EventContext, EventSink};
use shin::wire::alert::{Alert, AlertDescription, AlertParseError};
use shin::wire::record::{
    ContentType, HEADER_LEN, MAX_CIPHERTEXT_BODY, MAX_PLAINTEXT_BODY, PlaintextRecord, RecordError,
    RecordKeyError,
};

use super::buffer::Pending;
use super::sessions::{ClientSession, Session};
use super::status::{PeerClose, Phase};
use super::traffic::{Traffic, TrafficFailure};
use crate::error::Error;

const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HS_PLAIN: u8 = 22;
const REC_AEAD: u8 = 23;

pub(super) enum RecordAction {
    Application(usize),
    Control(bool),
}

pub(super) enum RecordFailure {
    Handshake(connection::Error),
    UnexpectedRecord,
    NotEstablished,
    Record(RecordError),
    RecordKey(RecordKeyError),
    PeerAlert(AlertDescription),
    MalformedAlert,
    SendOverflow,
    BufferUnavailable,
    EarlyDataUnsupported,
}

impl From<TrafficFailure> for RecordFailure {
    fn from(error: TrafficFailure) -> Self {
        match error {
            TrafficFailure::UnexpectedRecord => Self::UnexpectedRecord,
            TrafficFailure::NotEstablished => Self::NotEstablished,
            TrafficFailure::Record(error) => Self::Record(error),
            TrafficFailure::RecordKey(error) => Self::RecordKey(error),
            TrafficFailure::SendOverflow => Self::SendOverflow,
        }
    }
}

pub(super) trait FailurePolicy {
    type Failure;

    fn fail(error: RecordFailure) -> Self::Failure;
}

pub(super) struct IgnoreFailure;

impl FailurePolicy for IgnoreFailure {
    type Failure = ();

    #[cold]
    fn fail(_error: RecordFailure) {}
}

pub(super) struct ReportFailure;

impl FailurePolicy for ReportFailure {
    type Failure = Error;

    fn fail(error: RecordFailure) -> Error {
        match error {
            RecordFailure::Handshake(error) => Error::Handshake(error),
            RecordFailure::UnexpectedRecord => Error::UnexpectedRecord,
            RecordFailure::NotEstablished => Error::NotEstablished,
            RecordFailure::Record(error) => Error::Record(error),
            RecordFailure::RecordKey(error) => Error::RecordKey(error),
            RecordFailure::PeerAlert(error) => Error::PeerAlert(error),
            RecordFailure::MalformedAlert => Error::MalformedAlert,
            RecordFailure::SendOverflow => Error::SendOverflow,
            RecordFailure::BufferUnavailable => Error::BufferUnavailable,
            RecordFailure::EarlyDataUnsupported => Error::EarlyDataUnsupported,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RecordFrame {
    total: usize,
}

impl RecordFrame {
    pub(super) fn parse(input: &[u8]) -> Result<Option<Self>, RecordError> {
        if input.len() < HEADER_LEN {
            return Ok(None);
        }
        let body_len = u16::from_be_bytes([input[3], input[4]]) as usize;
        if body_len > MAX_CIPHERTEXT_BODY {
            return Err(RecordError::BodyTooLarge);
        }
        Ok(Some(Self {
            total: HEADER_LEN + body_len,
        }))
    }

    pub(super) fn complete(input: &[u8]) -> Result<Option<Self>, RecordError> {
        Ok(Self::parse(input)?.filter(|frame| input.len() >= frame.total))
    }

    pub(super) fn len(self) -> usize {
        self.total
    }
}

pub(super) struct RecordState<S> {
    pub(super) side: S,
    pub(super) traffic: Traffic,
}

pub(super) struct RecordEvents<'a> {
    phase: &'a mut Phase,
    pending: Pending<'a>,
    traffic: &'a mut Traffic,
}

impl<'a> RecordEvents<'a> {
    fn new(phase: &'a mut Phase, pending: Pending<'a>, traffic: &'a mut Traffic) -> Self {
        Self {
            phase,
            pending,
            traffic,
        }
    }

    fn absorb_send(&mut self, epoch: Epoch, data: &[u8]) -> Result<(), RecordFailure> {
        let pending = self
            .pending
            .try_buffer()
            .ok_or(RecordFailure::BufferUnavailable)?;
        match epoch {
            Epoch::Plaintext => encode_plaintext(pending, ContentType::Handshake, data),
            Epoch::Handshake => self
                .traffic
                .seal_handshake(pending, data)
                .map_err(RecordFailure::from),
            Epoch::Application => self
                .traffic
                .seal_application(pending, ContentType::Handshake, data)
                .map_err(RecordFailure::from),
            Epoch::EarlyData => Err(RecordFailure::EarlyDataUnsupported),
        }
    }

    fn absorb(&mut self, event: Event<'_>, context: EventContext) -> Result<(), RecordFailure> {
        match event {
            Event::Send { epoch, data } => self.absorb_send(epoch, data)?,
            Event::KeysReady {
                epoch,
                read_secret,
                write_secret,
            } => {
                let suite = context
                    .cipher_suite()
                    .ok_or(RecordFailure::UnexpectedRecord)?;
                self.traffic
                    .install(
                        epoch,
                        read_secret.as_slice(),
                        write_secret.as_slice(),
                        suite,
                    )
                    .map_err(RecordFailure::from)?;
            }
            Event::KeyUpdate { direction, secret } => {
                let suite = context
                    .cipher_suite()
                    .ok_or(RecordFailure::UnexpectedRecord)?;
                self.traffic
                    .update(direction, secret.as_slice(), suite)
                    .map_err(RecordFailure::from)?;
            }
            Event::Done => {
                *self.phase = Phase::Established;
            }
            Event::PeerExtension { .. }
            | Event::NewSessionTicket { .. }
            | Event::ResumptionSecret { .. }
            | Event::ZeroRttKeysReady { .. }
            | Event::EarlyDataAccepted
            | Event::EarlyDataRejected => {}
        }
        Ok(())
    }
}

impl EventSink for RecordEvents<'_> {
    type Error = RecordFailure;

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        self.absorb(event, context)
    }
}

impl<S: Session> RecordState<S> {
    pub(super) fn new(side: S) -> Self {
        Self {
            side,
            traffic: Traffic::default(),
        }
    }

    pub(super) fn send_key_update(
        &mut self,
        phase: &mut Phase,
        pending: Pending<'_>,
        request: bool,
    ) -> Result<(), Error> {
        self.drive::<ReportFailure>(phase, pending, |side, events| {
            side.send_key_update_into(request, events)
        })
    }

    pub(super) fn handle<P: FailurePolicy>(
        &mut self,
        phase: &mut Phase,
        peer_close: &mut PeerClose,
        pending: Pending<'_>,
        record: &mut [u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<RecordAction, P::Failure> {
        match record[0] {
            REC_CCS => Ok(RecordAction::Control(true)),
            REC_ALERT => self
                .classify_alert::<P>(
                    phase,
                    peer_close,
                    Alert::parse(&record[HEADER_LEN..]),
                    false,
                )
                .map(RecordAction::Control),
            REC_HS_PLAIN => self
                .handle_handshake::<P>(phase, pending, record, read)
                .map(RecordAction::Control),
            REC_AEAD => self.handle_aead::<P>(phase, peer_close, pending, record, read),
            _ => Err(P::fail(RecordFailure::UnexpectedRecord)),
        }
    }

    pub(super) fn stage_fatal_alert(&mut self, pending: &mut Pending<'_>, desc: AlertDescription) {
        stage_fatal_alert(&mut self.traffic, pending, desc);
    }

    fn handle_handshake<P: FailurePolicy>(
        &mut self,
        phase: &mut Phase,
        pending: Pending<'_>,
        record: &[u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<bool, P::Failure> {
        if record.len() > HEADER_LEN + MAX_PLAINTEXT_BODY {
            return Err(P::fail(RecordFailure::Record(RecordError::BodyTooLarge)));
        }
        let (parsed, consumed) = match PlaintextRecord::parse(record) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Err(P::fail(RecordFailure::UnexpectedRecord)),
            Err(error) => return Err(P::fail(RecordFailure::Record(error))),
        };
        debug_assert_eq!(consumed, record.len());
        self.drive_handshake::<P>(phase, pending, Epoch::Plaintext, parsed.body, read)?;
        Ok(true)
    }

    fn handle_aead<P: FailurePolicy>(
        &mut self,
        phase: &mut Phase,
        peer_close: &mut PeerClose,
        pending: Pending<'_>,
        record: &mut [u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<RecordAction, P::Failure> {
        let epoch = if *phase == Phase::Handshaking && self.traffic.handshake_ready() {
            Epoch::Handshake
        } else {
            Epoch::Application
        };
        let opener = match self.traffic.opener(*phase) {
            Ok(opener) => opener,
            Err(error) => return Err(P::fail(error.into())),
        };
        let opened = opener.open(record);
        let (content_type, range, consumed) = match opened {
            Ok(Some(opened)) => opened,
            Ok(None) => return Err(P::fail(RecordFailure::UnexpectedRecord)),
            Err(error) => {
                return self
                    .record_open_failed::<P>(phase, pending, error)
                    .map(RecordAction::Control);
            }
        };
        debug_assert_eq!(consumed, record.len());
        match content_type {
            ContentType::ApplicationData => {
                self.side.note_application_data();
                debug_assert_eq!(range.start, HEADER_LEN);
                Ok(RecordAction::Application(range.len()))
            }
            ContentType::Handshake => {
                self.drive_handshake::<P>(phase, pending, epoch, &record[range], read)?;
                Ok(RecordAction::Control(true))
            }
            ContentType::Alert => self
                .classify_alert::<P>(phase, peer_close, Alert::parse(&record[range]), true)
                .map(RecordAction::Control),
            ContentType::ChangeCipherSpec => Err(P::fail(RecordFailure::Record(
                RecordError::UnexpectedChangeCipherSpec,
            ))),
        }
    }

    fn classify_alert<P: FailurePolicy>(
        &mut self,
        phase: &mut Phase,
        peer_close: &mut PeerClose,
        parsed: Result<Alert, AlertParseError>,
        encrypted: bool,
    ) -> Result<bool, P::Failure> {
        let alert = match parsed {
            Ok(alert) => alert,
            Err(_) => {
                *phase = Phase::Closed;
                *peer_close = PeerClose::Fatal(AlertDescription::DecodeError);
                return Err(P::fail(RecordFailure::MalformedAlert));
            }
        };
        if encrypted && alert.description == AlertDescription::CloseNotify {
            *peer_close = PeerClose::CloseNotify;
            *phase = if self.traffic.application_ready() {
                Phase::PeerClosed
            } else {
                Phase::Closed
            };
            Ok(false)
        } else {
            *phase = Phase::Closed;
            *peer_close = PeerClose::Fatal(alert.description);
            Err(P::fail(RecordFailure::PeerAlert(alert.description)))
        }
    }

    fn record_open_failed<P: FailurePolicy>(
        &mut self,
        phase: &mut Phase,
        mut pending: Pending<'_>,
        error: RecordError,
    ) -> Result<bool, P::Failure> {
        let description = match error {
            RecordError::UnexpectedChangeCipherSpec => AlertDescription::UnexpectedMessage,
            _ => AlertDescription::BadRecordMac,
        };
        self.stage_fatal_alert(&mut pending, description);
        *phase = Phase::Closed;
        Err(P::fail(RecordFailure::Record(error)))
    }

    fn drive_handshake<P: FailurePolicy>(
        &mut self,
        phase: &mut Phase,
        pending: Pending<'_>,
        epoch: Epoch,
        data: &[u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<(), P::Failure> {
        self.drive::<P>(phase, pending, |side, events| {
            read(side, epoch, data, events)
        })
    }

    fn drive<P: FailurePolicy>(
        &mut self,
        phase: &mut Phase,
        pending: Pending<'_>,
        run: impl FnOnce(&mut S, &mut RecordEvents<'_>) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<(), P::Failure> {
        let mut events = RecordEvents::new(phase, pending, &mut self.traffic);
        let result = run(&mut self.side, &mut events);
        match result {
            Ok(()) => Ok(()),
            Err(DriveError::Protocol(error)) => {
                stage_fatal_alert(
                    events.traffic,
                    &mut events.pending,
                    error.alert().description,
                );
                *events.phase = Phase::Closed;
                Err(P::fail(RecordFailure::Handshake(error)))
            }
            Err(DriveError::Sink(error)) => Err(P::fail(error)),
        }
    }
}

impl<S: ClientSession> RecordState<S> {
    pub(super) fn start_client(
        &mut self,
        phase: &mut Phase,
        pending: Pending<'_>,
    ) -> Result<(), Error> {
        self.drive::<ReportFailure>(phase, pending, |side, events| side.start_into(events))
    }
}

fn stage_fatal_alert(traffic: &mut Traffic, pending: &mut Pending<'_>, desc: AlertDescription) {
    let Some(pending) = pending.try_buffer() else {
        return;
    };
    let alert = Alert::fatal(desc);
    if traffic.application_ready() {
        let _ = traffic.seal_application(pending, ContentType::Alert, &alert.body());
    } else {
        let _ = encode_plaintext(pending, ContentType::Alert, &alert.body());
    }
}

fn encode_plaintext(
    pending: &mut Buffer<Scratch>,
    content_type: ContentType,
    data: &[u8],
) -> Result<(), RecordFailure> {
    pending
        .try_fill(|spare| PlaintextRecord::encode_into_uninit(content_type, data, spare))
        .map_err(|error| match error {
            FillError::Fill(RecordError::BufferTooSmall) | FillError::Capacity => {
                RecordFailure::SendOverflow
            }
            FillError::Fill(error) => RecordFailure::Record(error),
        })
}
