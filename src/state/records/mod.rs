use o3::buffer::pool;
use shin::{
    connection,
    wire::{alert, handshake, record},
};

use crate::error;
use crate::state::{self, buffers, sessions, status};

pub(crate) mod events;
mod traffic;

const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HS_PLAIN: u8 = 22;
const REC_AEAD: u8 = 23;

pub(super) enum RecordAction {
    Application(usize),
    Control(Control),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Control {
    Continue,
    Stop,
}

impl Control {
    pub(super) fn status(self) -> status::Read {
        match self {
            Self::Continue => status::Read::Continue,
            Self::Stop => status::Read::Stop,
        }
    }
}

pub(crate) enum RecordFailure {
    Handshake(connection::Error),
    UnexpectedRecord,
    NotEstablished,
    Record(record::Error),
    RecordKey(record::KeyError),
    PeerAlert(alert::Description),
    MalformedAlert,
    SendOverflow,
    BufferUnavailable,
    EarlyDataUnsupported,
}

impl From<traffic::TrafficFailure> for RecordFailure {
    fn from(error: traffic::TrafficFailure) -> Self {
        match error {
            traffic::TrafficFailure::UnexpectedRecord => Self::UnexpectedRecord,
            traffic::TrafficFailure::NotEstablished => Self::NotEstablished,
            traffic::TrafficFailure::Record(error) => Self::Record(error),
            traffic::TrafficFailure::RecordKey(error) => Self::RecordKey(error),
            traffic::TrafficFailure::SendOverflow => Self::SendOverflow,
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
    type Failure = error::Error;

    fn fail(error: RecordFailure) -> error::Error {
        match error {
            RecordFailure::Handshake(error) => error::Error::Handshake(error),
            RecordFailure::UnexpectedRecord => error::Error::UnexpectedRecord,
            RecordFailure::NotEstablished => error::Error::NotEstablished,
            RecordFailure::Record(error) => error::Error::Record(error),
            RecordFailure::RecordKey(error) => error::Error::RecordKey(error),
            RecordFailure::PeerAlert(error) => error::Error::PeerAlert(error),
            RecordFailure::MalformedAlert => error::Error::MalformedAlert,
            RecordFailure::SendOverflow => error::Error::SendOverflow,
            RecordFailure::BufferUnavailable => error::Error::BufferUnavailable,
            RecordFailure::EarlyDataUnsupported => error::Error::EarlyDataUnsupported,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RecordFrame {
    total: usize,
}

impl RecordFrame {
    pub(super) fn parse(input: &[u8]) -> Result<Option<Self>, record::Error> {
        if input.len() < record::HEADER_LEN {
            return Ok(None);
        }
        let body_len = u16::from_be_bytes([input[3], input[4]]) as usize;
        if body_len > record::MAX_CIPHERTEXT_BODY {
            return Err(record::Error::BodyTooLarge);
        }
        Ok(Some(Self {
            total: record::HEADER_LEN + body_len,
        }))
    }

    pub(super) fn complete(input: &[u8]) -> Result<Option<Self>, record::Error> {
        Ok(Self::parse(input)?.filter(|frame| input.len() >= frame.total))
    }

    pub(super) fn len(self) -> usize {
        self.total
    }
}

pub(super) struct Records<S> {
    pub(super) side: S,
    pub(super) traffic: traffic::Traffic,
}

impl<S: sessions::Peer> Records<S> {
    pub(super) fn new(side: S) -> Self {
        Self {
            side,
            traffic: traffic::Traffic::default(),
        }
    }

    pub(super) fn send_key_update(
        &mut self,
        phase: &mut status::Phase,
        pending: buffers::Pending<'_, '_>,
        control: &mut state::PendingControl,
        request: handshake::KeyUpdateRequest,
    ) -> Result<(), error::Error> {
        self.drive::<ReportFailure>(phase, pending, control, |side, events| {
            side.send_key_update_into(request, events)
        })
    }

    pub(super) fn key_update_fits(&self, spare: usize) -> bool {
        self.traffic.key_update_fits(spare)
    }

    pub(super) fn send_pending_key_update_response(
        &mut self,
        phase: &mut status::Phase,
        pending: buffers::Pending<'_, '_>,
        control: &mut state::PendingControl,
    ) -> Result<(), error::Error> {
        let result = self.drive::<ReportFailure>(phase, pending, control, |side, events| {
            side.send_pending_key_update_response_into(events)
        });
        if result.is_ok() {
            control.key_update_response = false;
        }
        result
    }

    pub(super) fn fatal_alert_fits(&self, spare: usize) -> bool {
        self.traffic.fatal_alert_fits(spare)
    }

    pub(super) fn seal_fatal_alert_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'_>,
        description: alert::Description,
    ) -> Result<(), error::Error> {
        let alert = alert::Alert::fatal(description);
        if self.traffic.application_ready() {
            self.traffic
                .seal_application(output, record::ContentType::Alert, &alert.body())
                .map_err(error::Error::from)
        } else {
            encode_plaintext(output, record::ContentType::Alert, &alert.body())
                .map_err(ReportFailure::fail)
        }
    }

    pub(super) fn handle<P: FailurePolicy>(
        &mut self,
        phase: &mut status::Phase,
        peer_close: &mut status::PeerClose,
        control: &mut state::PendingControl,
        pending: buffers::Pending<'_, '_>,
        record: &mut [u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<RecordFailure>>,
    ) -> Result<RecordAction, P::Failure> {
        match record[0] {
            REC_CCS => Ok(RecordAction::Control(Control::Continue)),
            REC_ALERT => self
                .classify_alert::<P>(
                    phase,
                    peer_close,
                    alert::Alert::parse(&record[record::HEADER_LEN..]),
                    false,
                )
                .map(RecordAction::Control),
            REC_HS_PLAIN => self
                .handle_handshake::<P>(phase, control, pending, record, read)
                .map(RecordAction::Control),
            REC_AEAD => self.handle_aead::<P>(phase, peer_close, control, pending, record, read),
            _ => Err(P::fail(RecordFailure::UnexpectedRecord)),
        }
    }

    pub(super) fn stage_fatal_alert(
        &mut self,
        phase: status::Phase,
        pending: &mut buffers::Pending<'_, '_>,
        deferred: &mut Option<alert::Description>,
        desc: alert::Description,
    ) {
        stage_fatal_alert(&mut self.traffic, phase, pending, deferred, desc);
    }

    fn handle_handshake<P: FailurePolicy>(
        &mut self,
        phase: &mut status::Phase,
        control: &mut state::PendingControl,
        pending: buffers::Pending<'_, '_>,
        record: &[u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<RecordFailure>>,
    ) -> Result<Control, P::Failure> {
        if record.len() > record::HEADER_LEN + record::MAX_PLAINTEXT_BODY {
            return Err(P::fail(RecordFailure::Record(record::Error::BodyTooLarge)));
        }
        let (parsed, consumed) = match record::Plaintext::parse(record) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Err(P::fail(RecordFailure::UnexpectedRecord)),
            Err(error) => return Err(P::fail(RecordFailure::Record(error))),
        };
        debug_assert_eq!(consumed, record.len());
        self.drive_handshake::<P>(
            phase,
            control,
            pending,
            connection::Epoch::Plaintext,
            parsed.body,
            read,
        )?;
        Ok(Control::Continue)
    }

    fn handle_aead<P: FailurePolicy>(
        &mut self,
        phase: &mut status::Phase,
        peer_close: &mut status::PeerClose,
        control: &mut state::PendingControl,
        pending: buffers::Pending<'_, '_>,
        record: &mut [u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<RecordFailure>>,
    ) -> Result<RecordAction, P::Failure> {
        let epoch = if *phase == status::Phase::Handshaking && self.traffic.handshake_ready() {
            connection::Epoch::Handshake
        } else {
            connection::Epoch::Application
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
                    .record_open_failed::<P>(phase, control, pending, error)
                    .map(RecordAction::Control);
            }
        };
        debug_assert_eq!(consumed, record.len());
        match content_type {
            record::ContentType::ApplicationData => {
                self.side.note_application_data();
                debug_assert_eq!(range.start, record::HEADER_LEN);
                Ok(RecordAction::Application(range.len()))
            }
            record::ContentType::Handshake => {
                self.drive_handshake::<P>(phase, control, pending, epoch, &record[range], read)?;
                Ok(RecordAction::Control(Control::Continue))
            }
            record::ContentType::Alert => self
                .classify_alert::<P>(phase, peer_close, alert::Alert::parse(&record[range]), true)
                .map(RecordAction::Control),
            record::ContentType::ChangeCipherSpec => Err(P::fail(RecordFailure::Record(
                record::Error::UnexpectedChangeCipherSpec,
            ))),
        }
    }

    fn classify_alert<P: FailurePolicy>(
        &mut self,
        phase: &mut status::Phase,
        peer_close: &mut status::PeerClose,
        parsed: Result<alert::Alert, alert::Error>,
        encrypted: bool,
    ) -> Result<Control, P::Failure> {
        let alert = match parsed {
            Ok(alert) => alert,
            Err(_) => {
                *phase = status::Phase::Closed;
                *peer_close = status::PeerClose::Fatal(alert::Description::DecodeError);
                return Err(P::fail(RecordFailure::MalformedAlert));
            }
        };
        if encrypted && alert.description == alert::Description::CloseNotify {
            *peer_close = status::PeerClose::CloseNotify;
            *phase = if self.traffic.application_ready() {
                status::Phase::PeerClosed
            } else {
                status::Phase::Closed
            };
            Ok(Control::Stop)
        } else {
            *phase = status::Phase::Closed;
            *peer_close = status::PeerClose::Fatal(alert.description);
            Err(P::fail(RecordFailure::PeerAlert(alert.description)))
        }
    }

    fn record_open_failed<P: FailurePolicy>(
        &mut self,
        phase: &mut status::Phase,
        control: &mut state::PendingControl,
        mut pending: buffers::Pending<'_, '_>,
        error: record::Error,
    ) -> Result<Control, P::Failure> {
        let description = match error {
            record::Error::UnexpectedChangeCipherSpec => alert::Description::UnexpectedMessage,
            _ => alert::Description::BadRecordMac,
        };
        self.stage_fatal_alert(*phase, &mut pending, &mut control.fatal_alert, description);
        *phase = status::Phase::Closed;
        Err(P::fail(RecordFailure::Record(error)))
    }

    fn drive_handshake<P: FailurePolicy>(
        &mut self,
        phase: &mut status::Phase,
        control: &mut state::PendingControl,
        pending: buffers::Pending<'_, '_>,
        epoch: connection::Epoch,
        data: &[u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<RecordFailure>>,
    ) -> Result<(), P::Failure> {
        self.drive::<P>(phase, pending, control, |side, events| {
            read(side, epoch, data, events)
        })
    }

    fn drive<P: FailurePolicy>(
        &mut self,
        phase: &mut status::Phase,
        pending: buffers::Pending<'_, '_>,
        control: &mut state::PendingControl,
        run: impl FnOnce(
            &mut S,
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<RecordFailure>>,
    ) -> Result<(), P::Failure> {
        let mut events = events::RecordEvents::new(phase, pending, control, &mut self.traffic);
        let result = run(&mut self.side, &mut events);
        match result {
            Ok(()) => Ok(()),
            Err(connection::DriveError::Protocol(error)) => {
                stage_fatal_alert(
                    events.traffic,
                    *events.phase,
                    &mut events.pending,
                    &mut events.control.fatal_alert,
                    error.alert().description,
                );
                *events.phase = status::Phase::Closed;
                Err(P::fail(RecordFailure::Handshake(error)))
            }
            Err(connection::DriveError::Sink(error)) => Err(P::fail(error)),
        }
    }
}

impl<S: sessions::ClientPeer> Records<S> {
    pub(super) fn start_client(
        &mut self,
        phase: &mut status::Phase,
        pending: buffers::Pending<'_, '_>,
    ) -> Result<(), error::Error> {
        let mut control = state::PendingControl::default();
        self.drive::<ReportFailure>(phase, pending, &mut control, |side, events| {
            side.start_into(events)
        })
    }
}

fn stage_fatal_alert(
    traffic: &mut traffic::Traffic,
    phase: status::Phase,
    pending: &mut buffers::Pending<'_, '_>,
    deferred: &mut Option<alert::Description>,
    desc: alert::Description,
) {
    if phase != status::Phase::Handshaking {
        deferred.get_or_insert(desc);
        return;
    }
    let Some(pending) = pending.try_buffer() else {
        return;
    };
    let alert = alert::Alert::fatal(desc);
    if traffic.application_ready() {
        let _ = traffic.seal_application(pending, record::ContentType::Alert, &alert.body());
    } else {
        let _ = encode_plaintext(pending, record::ContentType::Alert, &alert.body());
    }
}

fn encode_plaintext(
    pending: &mut pool::BorrowedCursor<'_>,
    content_type: record::ContentType,
    data: &[u8],
) -> Result<(), RecordFailure> {
    let mut writer = pending.spare_writer();
    record::Plaintext::write_to(content_type, data, &mut writer).map_err(|error| match error {
        record::Error::BufferTooSmall => RecordFailure::SendOverflow,
        error => RecordFailure::Record(error),
    })
}
