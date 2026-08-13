use o3::buffer::pool;
use shin::{connection, wire::record};

use crate::state::status;
use crate::{error, staging};

const KEY_UPDATE_LEN: usize = staging::TLS13_RECORD_OVERHEAD + 4 + 1;
const FATAL_ALERT_LEN: usize = staging::TLS13_RECORD_OVERHEAD + 2;

#[derive(Clone, Copy)]
pub(in crate::state) enum TrafficFailure {
    UnexpectedRecord,
    NotEstablished,
    Record(record::Error),
    RecordKey(record::KeyError),
    SendOverflow,
}

impl From<record::KeyError> for TrafficFailure {
    fn from(error: record::KeyError) -> Self {
        Self::RecordKey(error)
    }
}

impl From<TrafficFailure> for error::Error {
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

#[derive(Default)]
struct Keys {
    opener: Option<record::Opener>,
    sealer: Option<record::Sealer>,
}

#[derive(Default)]
pub(in crate::state) struct Traffic {
    handshake: Keys,
    application: Keys,
}

impl Traffic {
    pub(in crate::state) fn handshake_ready(&self) -> bool {
        self.handshake.opener.is_some()
    }

    pub(in crate::state) fn application_ready(&self) -> bool {
        self.application.sealer.is_some()
    }

    pub(in crate::state) fn needs_key_update(&self) -> bool {
        self.application
            .sealer
            .as_ref()
            .is_some_and(record::Sealer::needs_key_update)
    }

    pub(in crate::state) fn key_update_fits(&self, spare: usize) -> bool {
        spare >= KEY_UPDATE_LEN
    }

    pub(in crate::state) fn fatal_alert_fits(&self, spare: usize) -> bool {
        spare >= FATAL_ALERT_LEN
    }

    pub(in crate::state) fn opener(
        &mut self,
        phase: status::Phase,
    ) -> Result<&mut record::Opener, TrafficFailure> {
        let opener = if phase == status::Phase::Handshaking {
            self.handshake.opener.as_mut()
        } else {
            self.application
                .opener
                .as_mut()
                .or(self.handshake.opener.as_mut())
        };
        opener.ok_or(TrafficFailure::UnexpectedRecord)
    }

    pub(in crate::state) fn seal_handshake(
        &mut self,
        output: &mut pool::BorrowedCursor<'_>,
        data: &[u8],
    ) -> Result<(), TrafficFailure> {
        let sealer = self
            .handshake
            .sealer
            .as_mut()
            .ok_or(TrafficFailure::UnexpectedRecord)?;
        seal(output, sealer, record::ContentType::Handshake, data)
    }

    pub(in crate::state) fn seal_application(
        &mut self,
        output: &mut pool::BorrowedCursor<'_>,
        content_type: record::ContentType,
        data: &[u8],
    ) -> Result<(), TrafficFailure> {
        let sealer = self
            .application
            .sealer
            .as_mut()
            .ok_or(TrafficFailure::NotEstablished)?;
        seal(output, sealer, content_type, data)
    }

    pub(in crate::state) fn write_application(
        &mut self,
        phase: status::Phase,
        output: &mut pool::BorrowedCursor<'_>,
        plaintext: &[u8],
    ) -> Result<usize, error::Error> {
        if phase != status::Phase::Established {
            return Err(error::Error::NotEstablished);
        }
        let mut consumed = 0;
        while consumed < plaintext.len() {
            let end = (consumed + record::MAX_PLAINTEXT_BODY).min(plaintext.len());
            let needed = end - consumed + staging::TLS13_RECORD_OVERHEAD;
            if output.spare_capacity() < needed {
                break;
            }
            self.seal_application(
                output,
                record::ContentType::ApplicationData,
                &plaintext[consumed..end],
            )?;
            consumed = end;
        }
        Ok(consumed)
    }

    pub(in crate::state) fn write_application_parts<'a>(
        &mut self,
        phase: status::Phase,
        output: &mut pool::BorrowedCursor<'_>,
        plaintext_len: usize,
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<usize, error::Error> {
        if phase != status::Phase::Established {
            return Err(error::Error::NotEstablished);
        }
        if plaintext_len > record::MAX_PLAINTEXT_BODY {
            return Err(error::Error::Record(record::Error::BodyTooLarge));
        }
        if output.spare_capacity() < plaintext_len + staging::TLS13_RECORD_OVERHEAD {
            return Ok(0);
        }
        let sealer = self
            .application
            .sealer
            .as_mut()
            .ok_or(error::Error::NotEstablished)?;
        let mut writer = output.spare_writer();
        sealer
            .seal_parts_to(
                record::ContentType::ApplicationData,
                plaintext_len,
                parts,
                &mut writer,
            )
            .map_err(|error| match error {
                record::Error::BufferTooSmall => error::Error::SendOverflow,
                error => error::Error::Record(error),
            })?;
        Ok(plaintext_len)
    }

    pub(in crate::state) fn install(
        &mut self,
        epoch: connection::Epoch,
        read_secret: &[u8],
        write_secret: &[u8],
        suite: record::CipherSuite,
    ) -> Result<(), TrafficFailure> {
        let keys = match epoch {
            connection::Epoch::Handshake => &mut self.handshake,
            connection::Epoch::Application => &mut self.application,
            connection::Epoch::Plaintext | connection::Epoch::EarlyData => return Ok(()),
        };
        keys.opener = Some(record::Opener::with_suite(read_secret, suite)?);
        keys.sealer = Some(record::Sealer::with_suite(write_secret, suite)?);
        Ok(())
    }

    pub(in crate::state) fn update(
        &mut self,
        direction: connection::KeyDirection,
        secret: &[u8],
        suite: record::CipherSuite,
    ) -> Result<(), TrafficFailure> {
        match direction {
            connection::KeyDirection::Read => {
                self.application.opener = Some(record::Opener::with_suite(secret, suite)?);
            }
            connection::KeyDirection::Write => {
                self.application.sealer = Some(record::Sealer::with_suite(secret, suite)?);
            }
        }
        Ok(())
    }
}

fn seal(
    output: &mut pool::BorrowedCursor<'_>,
    sealer: &mut record::Sealer,
    content_type: record::ContentType,
    data: &[u8],
) -> Result<(), TrafficFailure> {
    let mut writer = output.spare_writer();
    sealer
        .seal_to(content_type, data, &mut writer)
        .map_err(|error| match error {
            record::Error::BufferTooSmall => TrafficFailure::SendOverflow,
            error => TrafficFailure::Record(error),
        })
}
