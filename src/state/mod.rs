use o3::buffer::{self, pool};
use shin::server::{config, workspace};
use shin::wire::{alert, handshake, record};

use crate::state::api::capabilities::{Status as _, Write as _};
use crate::state::sessions::{clients, servers};
use crate::{clock, error};

pub mod api;
pub(crate) mod buffers;
#[doc(hidden)]
pub mod direct;
mod records;
pub mod sessions;
#[doc(hidden)]
pub mod staged;
pub mod status;

pub struct State<'d, S: sessions::Peer> {
    record: records::Records<S>,
    phase: status::Phase,
    buffers: buffers::Buffers<'d>,
    control: PendingControl,
    peer_close: status::PeerClose,
}

#[derive(Default)]
struct PendingControl {
    fatal_alert: Option<alert::Description>,
    key_update_response: bool,
}

impl<'d, const ID: u8> State<'d, clients::Pooled<'d, ID>> {
    pub(crate) fn from_client(
        session: clients::Pooled<'d, ID>,
        buffers: buffers::Buffers<'d>,
    ) -> Result<Self, error::Error> {
        let mut state = Self::empty(session, buffers);
        state
            .record
            .start_client(&mut state.phase, state.buffers.pending_output())?;
        Ok(state)
    }
}

impl<'d, G, V, const DOMAIN: u8> State<'d, servers::Pooled<'d, DOMAIN, G, V>>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(crate) fn from_server_pool(
        clock: clock::Clock,
        recv: &'d buffer::Pool,
        send: &'d buffer::Pool,
        sessions: &'d workspace::Pool<clock::Clock, V, DOMAIN, G>,
    ) -> Result<Self, error::Error> {
        let session =
            servers::Pooled::new_tls(sessions, clock).ok_or(error::Error::BufferUnavailable)?;
        Ok(Self::empty(session, buffers::Buffers::pooled(recv, send)))
    }
}

pub(crate) trait Internals<'d, S: sessions::Peer> {
    fn empty(session: S, buffers: buffers::Buffers<'d>) -> Self;
    fn seal_app(
        &mut self,
        content_type: record::ContentType,
        data: &[u8],
    ) -> Result<(), error::Error>;
    fn write_app_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
        plaintext: &[u8],
    ) -> Result<usize, error::Error>;
    fn write_app_parts_into<'a>(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
        plaintext_len: usize,
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<usize, error::Error>;
    fn maybe_auto_key_update(&mut self) -> Result<(), error::Error>;
    fn maybe_auto_key_update_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
    ) -> Result<(), error::Error>;
    fn seal_closing_alert(&mut self, alert: alert::Alert) -> Result<(), error::Error>;
    fn seal_closing_alert_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
        alert: alert::Alert,
    ) -> Result<(), error::Error>;
    fn fatal_overflow(&mut self) -> error::Error;
    fn reserve_recv_buffer(&mut self) -> bool;
    fn release_empty_recv_buffer(&mut self) -> bool;
    fn swap_pending_buffer(&mut self, pending: &mut Option<pool::BorrowedCursor<'d>>);
    fn pending_pool(&self) -> &'d buffer::Pool;
    fn has_pending_control(&self) -> bool;
    fn drain_pending_control_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
    ) -> Result<(), error::Error>;
    fn drain_pending_control(&mut self) -> Result<(), error::Error>;
}

impl<'d, S: sessions::Peer> Internals<'d, S> for State<'d, S> {
    fn empty(session: S, buffers: buffers::Buffers<'d>) -> Self {
        Self {
            record: records::Records::new(session),
            phase: status::Phase::Handshaking,
            buffers,
            control: PendingControl::default(),
            peer_close: status::PeerClose::Open,
        }
    }

    fn seal_app(
        &mut self,
        content_type: record::ContentType,
        data: &[u8],
    ) -> Result<(), error::Error> {
        let mut pending = self.buffers.pending_output();
        self.record
            .traffic
            .seal_application(
                pending
                    .try_buffer()
                    .ok_or(error::Error::BufferUnavailable)?,
                content_type,
                data,
            )
            .map_err(error::Error::from)
    }

    fn write_app_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
        plaintext: &[u8],
    ) -> Result<usize, error::Error> {
        let consumed = self
            .record
            .traffic
            .write_application(self.phase, output, plaintext)?;
        self.maybe_auto_key_update_into(output)?;
        Ok(consumed)
    }

    fn write_app_parts_into<'a>(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
        plaintext_len: usize,
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<usize, error::Error> {
        let consumed = self.record.traffic.write_application_parts(
            self.phase,
            output,
            plaintext_len,
            parts,
        )?;
        self.maybe_auto_key_update_into(output)?;
        Ok(consumed)
    }

    fn maybe_auto_key_update(&mut self) -> Result<(), error::Error> {
        if self.record.traffic.needs_key_update()
            && !self.is_closed()
            && self
                .record
                .traffic
                .key_update_fits(self.buffers.pending_spare())
        {
            self.send_key_update(handshake::KeyUpdateRequest::NotRequested)?;
        }
        Ok(())
    }

    fn maybe_auto_key_update_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
    ) -> Result<(), error::Error> {
        if self.record.traffic.needs_key_update()
            && !self.is_closed()
            && self.record.traffic.key_update_fits(output.spare_capacity())
        {
            self.record.send_key_update(
                &mut self.phase,
                buffers::Pending::Borrowed(output),
                &mut self.control,
                handshake::KeyUpdateRequest::NotRequested,
            )?;
        }
        Ok(())
    }

    fn seal_closing_alert(&mut self, alert: alert::Alert) -> Result<(), error::Error> {
        if matches!(self.phase, status::Phase::Closed) {
            return Ok(());
        }
        if !self.record.traffic.application_ready() {
            return Err(error::Error::NotEstablished);
        }
        self.seal_app(record::ContentType::Alert, &alert.body())?;
        self.phase = status::Phase::Closed;
        Ok(())
    }

    fn seal_closing_alert_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
        alert: alert::Alert,
    ) -> Result<(), error::Error> {
        if matches!(self.phase, status::Phase::Closed) {
            return Ok(());
        }
        if !self.record.traffic.application_ready() {
            return Err(error::Error::NotEstablished);
        }
        self.record
            .traffic
            .seal_application(output, record::ContentType::Alert, &alert.body())?;
        self.phase = status::Phase::Closed;
        Ok(())
    }

    fn fatal_overflow(&mut self) -> error::Error {
        self.record.stage_fatal_alert(
            self.phase,
            &mut self.buffers.pending_output(),
            &mut self.control.fatal_alert,
            alert::Description::RecordOverflow,
        );
        self.phase = status::Phase::Closed;
        error::Error::ReceiveOverflow
    }

    fn reserve_recv_buffer(&mut self) -> bool {
        self.buffers.reserve_recv()
    }

    fn release_empty_recv_buffer(&mut self) -> bool {
        self.buffers.release_recv_if_empty()
    }

    fn swap_pending_buffer(&mut self, pending: &mut Option<pool::BorrowedCursor<'d>>) {
        let state_pending = self.buffers.pending.take();
        self.buffers.pending = pending.take();
        *pending = state_pending;
    }

    fn pending_pool(&self) -> &'d buffer::Pool {
        self.buffers.pending_pool()
    }

    fn has_pending_control(&self) -> bool {
        self.control.fatal_alert.is_some()
            || (self.phase != status::Phase::Closed && self.control.key_update_response)
    }

    fn drain_pending_control_into(
        &mut self,
        output: &mut pool::BorrowedCursor<'d>,
    ) -> Result<(), error::Error> {
        drain_pending_control_into(&mut self.record, &mut self.phase, &mut self.control, output)
    }

    fn drain_pending_control(&mut self) -> Result<(), error::Error> {
        if !self.has_pending_control() {
            return Ok(());
        }
        let Self {
            record,
            phase,
            buffers,
            control,
            ..
        } = self;
        let mut pending = buffers.pending_output();
        let Some(output) = pending.try_buffer() else {
            return Ok(());
        };
        drain_pending_control_into(record, phase, control, output)
    }
}

fn drain_pending_control_into<S: sessions::Peer>(
    record: &mut records::Records<S>,
    phase: &mut status::Phase,
    control: &mut PendingControl,
    output: &mut pool::BorrowedCursor<'_>,
) -> Result<(), error::Error> {
    if let Some(description) = control.fatal_alert {
        if !record.fatal_alert_fits(output.spare_capacity()) {
            return Ok(());
        }
        record.seal_fatal_alert_into(output, description)?;
        control.fatal_alert = None;
        return Ok(());
    }
    if *phase != status::Phase::Closed
        && control.key_update_response
        && record.key_update_fits(output.spare_capacity())
    {
        record.send_pending_key_update_response(
            phase,
            buffers::Pending::Borrowed(output),
            control,
        )?;
    }
    Ok(())
}
