use dope_net::wire::buffered::{Buffer, FillError, Scratch};
use shin::connection::{Epoch, KeyDirection};
use shin::wire::record::{
    CipherSuite, ContentType, MAX_PLAINTEXT_BODY, Opener, RecordError, RecordKeyError, Sealer,
};

use super::{buffer::Buffers, status::Phase};
use crate::error::Error;
use crate::staging::TLS13_RECORD_OVERHEAD;

const KEY_UPDATE_LEN: usize = TLS13_RECORD_OVERHEAD + 4 + 1;

#[derive(Clone, Copy)]
pub(super) enum TrafficFailure {
    UnexpectedRecord,
    NotEstablished,
    Record(RecordError),
    RecordKey(RecordKeyError),
    SendOverflow,
}

impl From<RecordKeyError> for TrafficFailure {
    fn from(error: RecordKeyError) -> Self {
        Self::RecordKey(error)
    }
}

impl From<TrafficFailure> for Error {
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
    opener: Option<Opener>,
    sealer: Option<Sealer>,
}

#[derive(Default)]
pub(super) struct Traffic {
    handshake: Keys,
    application: Keys,
}

impl Traffic {
    pub(super) fn handshake_ready(&self) -> bool {
        self.handshake.opener.is_some()
    }

    pub(super) fn application_ready(&self) -> bool {
        self.application.sealer.is_some()
    }

    pub(super) fn needs_key_update(&self) -> bool {
        self.application
            .sealer
            .as_ref()
            .is_some_and(Sealer::needs_key_update)
    }

    pub(super) fn key_update_fits(&self, spare: usize) -> bool {
        spare >= KEY_UPDATE_LEN
    }

    pub(super) fn opener(&mut self, phase: Phase) -> Result<&mut Opener, TrafficFailure> {
        let opener = if phase == Phase::Handshaking {
            self.handshake.opener.as_mut()
        } else {
            self.application
                .opener
                .as_mut()
                .or(self.handshake.opener.as_mut())
        };
        opener.ok_or(TrafficFailure::UnexpectedRecord)
    }

    pub(super) fn seal_handshake(
        &mut self,
        output: &mut Buffer<Scratch>,
        data: &[u8],
    ) -> Result<(), TrafficFailure> {
        let sealer = self
            .handshake
            .sealer
            .as_mut()
            .ok_or(TrafficFailure::UnexpectedRecord)?;
        seal(output, sealer, ContentType::Handshake, data)
    }

    pub(super) fn seal_application(
        &mut self,
        output: &mut Buffer<Scratch>,
        content_type: ContentType,
        data: &[u8],
    ) -> Result<(), TrafficFailure> {
        let sealer = self
            .application
            .sealer
            .as_mut()
            .ok_or(TrafficFailure::NotEstablished)?;
        seal(output, sealer, content_type, data)
    }

    pub(super) fn write_application(
        &mut self,
        phase: Phase,
        output: &mut Buffer<Scratch>,
        plaintext: &[u8],
    ) -> Result<usize, Error> {
        if phase != Phase::Established {
            return Err(Error::NotEstablished);
        }
        let mut consumed = 0;
        while consumed < plaintext.len() {
            let end = (consumed + MAX_PLAINTEXT_BODY).min(plaintext.len());
            let needed = end - consumed + TLS13_RECORD_OVERHEAD;
            if output.spare_capacity() < needed {
                break;
            }
            self.seal_application(
                output,
                ContentType::ApplicationData,
                &plaintext[consumed..end],
            )?;
            consumed = end;
        }
        Ok(consumed)
    }

    pub(super) fn write_application_parts<'a>(
        &mut self,
        phase: Phase,
        output: &mut Buffer<Scratch>,
        plaintext_len: usize,
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<usize, Error> {
        if phase != Phase::Established {
            return Err(Error::NotEstablished);
        }
        if plaintext_len > MAX_PLAINTEXT_BODY {
            return Err(Error::Record(RecordError::BodyTooLarge));
        }
        if output.spare_capacity() < plaintext_len + TLS13_RECORD_OVERHEAD {
            return Ok(0);
        }
        let sealer = self
            .application
            .sealer
            .as_mut()
            .ok_or(Error::NotEstablished)?;
        output
            .try_fill(|spare| {
                sealer.seal_parts_into_uninit(
                    ContentType::ApplicationData,
                    plaintext_len,
                    parts,
                    spare,
                )
            })
            .map_err(Buffers::fill_error)?;
        Ok(plaintext_len)
    }

    pub(super) fn install(
        &mut self,
        epoch: Epoch,
        read_secret: &[u8],
        write_secret: &[u8],
        suite: CipherSuite,
    ) -> Result<(), TrafficFailure> {
        let keys = match epoch {
            Epoch::Handshake => &mut self.handshake,
            Epoch::Application => &mut self.application,
            Epoch::Plaintext | Epoch::EarlyData => return Ok(()),
        };
        keys.opener = Some(Opener::with_suite(read_secret, suite)?);
        keys.sealer = Some(Sealer::with_suite(write_secret, suite)?);
        Ok(())
    }

    pub(super) fn update(
        &mut self,
        direction: KeyDirection,
        secret: &[u8],
        suite: CipherSuite,
    ) -> Result<(), TrafficFailure> {
        match direction {
            KeyDirection::Read => {
                self.application.opener = Some(Opener::with_suite(secret, suite)?);
            }
            KeyDirection::Write => {
                self.application.sealer = Some(Sealer::with_suite(secret, suite)?);
            }
        }
        Ok(())
    }
}

fn seal(
    output: &mut Buffer<Scratch>,
    sealer: &mut Sealer,
    content_type: ContentType,
    data: &[u8],
) -> Result<(), TrafficFailure> {
    output
        .try_fill(|spare| sealer.seal_into_uninit(content_type, data, spare))
        .map_err(|error| match error {
            FillError::Fill(RecordError::BufferTooSmall) | FillError::Capacity => {
                TrafficFailure::SendOverflow
            }
            FillError::Fill(error) => TrafficFailure::Record(error),
        })
}
