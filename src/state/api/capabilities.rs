use shin::wire::{alert, handshake};

use crate::error;
use crate::state::Internals as _;
use crate::state::{self, sessions, status};

pub trait Write {
    fn pending_send_slice(&self) -> &[u8];
    fn consume_pending_send(&mut self, count: usize) -> Result<(), error::Error>;
    fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, error::Error>;
    fn send_key_update(&mut self, request: handshake::KeyUpdateRequest)
    -> Result<(), error::Error>;
    fn send_close_notify(&mut self) -> Result<(), error::Error>;
    fn send_fatal_alert(&mut self, description: alert::Description) -> Result<(), error::Error>;
}

pub trait Status {
    #[doc(hidden)]
    fn has_staged_recv(&self) -> bool;
    #[doc(hidden)]
    fn staged_recv(&self) -> &[u8];
    fn can_close_notify(&self) -> bool;
    fn peer_close(&self) -> status::PeerClose;
    fn peer_eof(&mut self) -> Result<(), error::Error>;
    fn is_handshaking(&self) -> bool;
    fn is_established(&self) -> bool;
    fn is_closed(&self) -> bool;
    fn phase(&self) -> status::Phase;
    fn selected_alpn(&self) -> Option<&[u8]>;
}

impl<S: sessions::Peer> Write for state::State<'_, S> {
    fn pending_send_slice(&self) -> &[u8] {
        self.buffers.pending()
    }

    fn consume_pending_send(&mut self, count: usize) -> Result<(), error::Error> {
        self.buffers
            .try_consume_pending(count)
            .then_some(())
            .ok_or(error::Error::InvalidBufferProgress)?;
        self.drain_pending_control()
    }

    fn write_app(&mut self, plaintext: &[u8]) -> Result<usize, error::Error> {
        self.drain_pending_control()?;
        if self.has_pending_control() {
            return Ok(0);
        }
        let mut pending = self.buffers.pending_output();
        let consumed = self.record.traffic.write_application(
            self.phase,
            pending
                .try_buffer()
                .ok_or(error::Error::BufferUnavailable)?,
            plaintext,
        )?;
        self.maybe_auto_key_update()?;
        Ok(consumed)
    }

    fn send_key_update(
        &mut self,
        request: handshake::KeyUpdateRequest,
    ) -> Result<(), error::Error> {
        if !self.is_established() {
            return Err(error::Error::NotEstablished);
        }
        self.record.send_key_update(
            &mut self.phase,
            self.buffers.pending_output(),
            &mut self.control,
            request,
        )
    }

    fn send_close_notify(&mut self) -> Result<(), error::Error> {
        self.drain_pending_control()?;
        self.seal_closing_alert(alert::Alert::close_notify())
    }

    fn send_fatal_alert(&mut self, description: alert::Description) -> Result<(), error::Error> {
        self.seal_closing_alert(alert::Alert::fatal(description))
    }
}

impl<S: sessions::Peer> Status for state::State<'_, S> {
    fn has_staged_recv(&self) -> bool {
        !self.buffers.recv().is_empty()
    }

    fn staged_recv(&self) -> &[u8] {
        self.buffers.recv()
    }

    fn can_close_notify(&self) -> bool {
        matches!(
            self.phase,
            status::Phase::Established | status::Phase::PeerClosed
        ) && self.record.traffic.application_ready()
    }

    fn peer_close(&self) -> status::PeerClose {
        self.peer_close
    }

    fn peer_eof(&mut self) -> Result<(), error::Error> {
        if self.peer_close == status::PeerClose::Open {
            self.peer_close = status::PeerClose::Truncated;
            self.phase = status::Phase::Closed;
            return Err(error::Error::Truncated);
        }
        Ok(())
    }

    fn is_handshaking(&self) -> bool {
        self.phase == status::Phase::Handshaking
    }

    fn is_established(&self) -> bool {
        self.phase == status::Phase::Established
    }

    fn is_closed(&self) -> bool {
        matches!(
            self.phase,
            status::Phase::PeerClosed | status::Phase::Closed
        )
    }

    fn phase(&self) -> status::Phase {
        self.phase
    }

    fn selected_alpn(&self) -> Option<&[u8]> {
        self.record.side.selected_alpn()
    }
}
