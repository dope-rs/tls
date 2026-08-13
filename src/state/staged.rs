use std::mem;

use o3::buffer::bytes;
use shin::{connection, wire::record};

use crate::error;
use crate::state::Internals as _;
use crate::state::api::capabilities::Status as _;
use crate::state::records::events;
use crate::state::{self, records, sessions, status};

#[doc(hidden)]
#[must_use]
pub struct WireRead<'d> {
    consumed: usize,
    chunk: Option<bytes::Bytes<bytes::Pooled<'d>>>,
    status: status::Read,
}

const _: () = assert!(
    mem::size_of::<WireRead<'static>>()
        <= mem::size_of::<(
            usize,
            Option<bytes::Bytes<bytes::Pooled<'static>>>,
            bool,
            bool,
        )>()
);

impl<'d> WireRead<'d> {
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    pub fn status(&self) -> status::Read {
        self.status
    }

    pub fn into_chunk(self) -> Option<bytes::Bytes<bytes::Pooled<'d>>> {
        self.chunk
    }

    pub(crate) fn fail(&mut self) {
        self.status = status::Read::Failed;
    }
}

pub(crate) struct Reader<'a, 'd, S: sessions::Peer> {
    state: &'a mut state::State<'d, S>,
}

impl<'a, 'd, S: sessions::Peer> Reader<'a, 'd, S> {
    pub(crate) fn new(state: &'a mut state::State<'d, S>) -> Self {
        Self { state }
    }

    pub(super) fn read(
        &mut self,
        bytes: &[u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
        receive: &mut impl FnMut(&[u8]),
    ) -> Result<(), error::Error> {
        let mut rest = bytes;
        loop {
            let take = self
                .state
                .buffers
                .append_recv(rest)
                .map_err(|_| error::Error::ReceiveOverflow)?;
            rest = &rest[take..];
            while self.consume_one_record(read, receive)? == records::Control::Continue {}
            if rest.is_empty() {
                return Ok(());
            }
            if take == 0 {
                return Err(error::Error::Record(record::Error::BodyTooLarge));
            }
        }
    }

    pub(crate) fn read_one_wire(
        &mut self,
        bytes: &[u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
    ) -> WireRead<'d> {
        match self.read_one_wire_result(bytes, read) {
            Ok((consumed, chunk, control)) => WireRead {
                consumed,
                chunk,
                status: control.status(),
            },
            Err(_) => WireRead {
                consumed: bytes.len(),
                chunk: None,
                status: status::Read::Failed,
            },
        }
    }

    fn read_one_wire_result(
        &mut self,
        bytes: &[u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
    ) -> Result<
        (
            usize,
            Option<bytes::Bytes<bytes::Pooled<'d>>>,
            records::Control,
        ),
        error::Error,
    > {
        let mut consumed = 0;
        if self.state.buffers.recv().len() < record::HEADER_LEN {
            let needed = record::HEADER_LEN - self.state.buffers.recv().len();
            let take = needed.min(bytes.len());
            self.state
                .buffers
                .append_recv(&bytes[..take])
                .map_err(|_| error::Error::ReceiveOverflow)?;
            consumed += take;
            if self.state.buffers.recv().len() < record::HEADER_LEN {
                return Ok((consumed, None, records::Control::Continue));
            }
        }
        let Some(frame) = records::RecordFrame::parse(self.state.buffers.recv())? else {
            return Ok((consumed, None, records::Control::Continue));
        };
        let total = frame.len();
        if self.state.buffers.recv().len() < total {
            let needed = total - self.state.buffers.recv().len();
            let take = needed.min(bytes.len() - consumed);
            self.state
                .buffers
                .append_recv(&bytes[consumed..consumed + take])
                .map_err(|_| error::Error::ReceiveOverflow)?;
            consumed += take;
            if self.state.buffers.recv().len() < total {
                return Ok((consumed, None, records::Control::Continue));
            }
        }
        let action = self.handle_record(total, read)?;
        let (chunk, control) = self.finish_wire_record(total, action)?;
        Ok((consumed, chunk, control))
    }

    fn consume_one_record(
        &mut self,
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
        receive: &mut impl FnMut(&[u8]),
    ) -> Result<records::Control, error::Error> {
        if self.state.is_closed() {
            return Ok(records::Control::Stop);
        }
        let Some(frame) = records::RecordFrame::complete(self.state.buffers.recv())? else {
            return Ok(records::Control::Stop);
        };
        let total = frame.len();
        let action = self.handle_record(total, read)?;
        self.finish_record(total, action, receive)
    }

    fn handle_record(
        &mut self,
        total: usize,
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
    ) -> Result<records::RecordAction, error::Error> {
        let state::State {
            record: state,
            phase,
            buffers,
            control,
            peer_close,
        } = &mut *self.state;
        let (record, pending) = buffers.recv_record_and_pending(total)?;
        state.handle::<records::ReportFailure>(phase, peer_close, control, pending, record, read)
    }

    fn finish_record(
        &mut self,
        total: usize,
        action: records::RecordAction,
        receive: &mut impl FnMut(&[u8]),
    ) -> Result<records::Control, error::Error> {
        let control = match action {
            records::RecordAction::Application(plaintext_len) => {
                let range = record::HEADER_LEN..record::HEADER_LEN + plaintext_len;
                if !range.is_empty() {
                    receive(&self.state.buffers.recv()[range]);
                }
                records::Control::Continue
            }
            records::RecordAction::Control(control) => control,
        };
        if !self.state.buffers.try_consume_recv(total) {
            return Err(error::Error::InvalidBufferProgress);
        }
        Ok(control)
    }

    fn finish_wire_record(
        &mut self,
        total: usize,
        action: records::RecordAction,
    ) -> Result<(Option<bytes::Bytes<bytes::Pooled<'d>>>, records::Control), error::Error> {
        match action {
            records::RecordAction::Application(plaintext_len) => {
                let range = record::HEADER_LEN..record::HEADER_LEN + plaintext_len;
                let empty = range.is_empty();
                let Some(chunk) = self.state.buffers.take_recv_range(range) else {
                    return Err(self.state.fatal_overflow());
                };
                Ok(((!empty).then_some(chunk), records::Control::Continue))
            }
            records::RecordAction::Control(control) => {
                if !self.state.buffers.try_consume_recv(total) {
                    return Err(error::Error::InvalidBufferProgress);
                }
                Ok((None, control))
            }
        }
    }
}
