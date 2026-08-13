use shin::{connection, wire::record};

use crate::state::records::{self, traffic};
use crate::state::{self, buffers, status};

pub(crate) struct RecordEvents<'a, 'd> {
    pub(super) phase: &'a mut status::Phase,
    pub(super) pending: buffers::Pending<'a, 'd>,
    pub(super) control: &'a mut state::PendingControl,
    pub(super) traffic: &'a mut traffic::Traffic,
}

impl<'a, 'd> RecordEvents<'a, 'd> {
    pub(super) fn new(
        phase: &'a mut status::Phase,
        pending: buffers::Pending<'a, 'd>,
        control: &'a mut state::PendingControl,
        traffic: &'a mut traffic::Traffic,
    ) -> Self {
        Self {
            phase,
            pending,
            control,
            traffic,
        }
    }

    fn absorb_send(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
    ) -> Result<(), records::RecordFailure> {
        let pending = self
            .pending
            .try_buffer()
            .ok_or(records::RecordFailure::BufferUnavailable)?;
        match epoch {
            connection::Epoch::Plaintext => {
                records::encode_plaintext(pending, record::ContentType::Handshake, data)
            }
            connection::Epoch::Handshake => self
                .traffic
                .seal_handshake(pending, data)
                .map_err(records::RecordFailure::from),
            connection::Epoch::Application => self
                .traffic
                .seal_application(pending, record::ContentType::Handshake, data)
                .map_err(records::RecordFailure::from),
            connection::Epoch::EarlyData => Err(records::RecordFailure::EarlyDataUnsupported),
        }
    }

    fn absorb(
        &mut self,
        event: connection::Event<'_>,
        context: connection::EventContext,
    ) -> Result<(), records::RecordFailure> {
        match event {
            connection::Event::Send { epoch, data } => self.absorb_send(epoch, data)?,
            connection::Event::KeysReady {
                epoch,
                read_secret,
                write_secret,
            } => {
                let suite = context
                    .cipher_suite()
                    .ok_or(records::RecordFailure::UnexpectedRecord)?;
                self.traffic
                    .install(
                        epoch,
                        read_secret.as_slice(),
                        write_secret.as_slice(),
                        suite,
                    )
                    .map_err(records::RecordFailure::from)?;
            }
            connection::Event::KeyUpdate { direction, secret } => {
                let suite = context
                    .cipher_suite()
                    .ok_or(records::RecordFailure::UnexpectedRecord)?;
                self.traffic
                    .update(direction, secret.as_slice(), suite)
                    .map_err(records::RecordFailure::from)?;
                self.control.key_update_response |= context.key_update_response_requested();
            }
            connection::Event::Done => *self.phase = status::Phase::Established,
            connection::Event::PeerExtension { .. }
            | connection::Event::NewSessionTicket(_)
            | connection::Event::ZeroRttKeysReady { .. }
            | connection::Event::EarlyDataAccepted
            | connection::Event::EarlyDataRejected => {}
        }
        Ok(())
    }
}

impl connection::EventSink for RecordEvents<'_, '_> {
    type Error = records::RecordFailure;

    fn event(
        &mut self,
        event: connection::Event<'_>,
        context: connection::EventContext,
    ) -> Result<(), Self::Error> {
        self.absorb(event, context)
    }
}
