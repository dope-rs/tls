use dope_net::wire::buffered::{Buffer, Scratch};
use shin::{
    Epoch, KeyDirection,
    record::{CipherSuite, ContentType, MAX_PLAINTEXT_BODY, Opener, Sealer},
};

use super::{buffer::Buffers, status::Phase};
use crate::error::Error;
use crate::staging::TLS13_RECORD_OVERHEAD;

const KEY_UPDATE_LEN: usize = TLS13_RECORD_OVERHEAD + 4 + 1;

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

    pub(super) fn opener(&mut self, phase: Phase) -> Result<&mut Opener, Error> {
        let opener = if phase == Phase::Handshaking {
            self.handshake.opener.as_mut()
        } else {
            self.application
                .opener
                .as_mut()
                .or(self.handshake.opener.as_mut())
        };
        opener.ok_or(Error::UnexpectedRecord)
    }

    pub(super) fn seal_handshake(
        &mut self,
        output: &mut Buffer<Scratch>,
        data: &[u8],
    ) -> Result<(), Error> {
        let sealer = self
            .handshake
            .sealer
            .as_mut()
            .ok_or(Error::UnexpectedRecord)?;
        seal(output, sealer, ContentType::Handshake, data)
    }

    pub(super) fn seal_application(
        &mut self,
        output: &mut Buffer<Scratch>,
        content_type: ContentType,
        data: &[u8],
    ) -> Result<(), Error> {
        let sealer = self
            .application
            .sealer
            .as_mut()
            .ok_or(Error::NotEstablished)?;
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

    pub(super) fn install(
        &mut self,
        epoch: Epoch,
        read_secret: &[u8],
        write_secret: &[u8],
        suite: CipherSuite,
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
) -> Result<(), Error> {
    output
        .try_fill(|spare| sealer.seal_into_uninit(content_type, data, spare))
        .map_err(Buffers::fill_error)
}
