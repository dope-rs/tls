use shin::connection::{DriveError, Epoch};
use shin::wire::record::{HEADER_LEN, RecordError};

use super::State;
use super::record::{RecordAction, RecordEvents, RecordFailure, RecordFrame, ReportFailure};
use super::sessions::Session;
use crate::error::Error;
use dope_net::{Bytes, Retained};

pub(super) struct WireRead {
    pub(super) consumed: usize,
    pub(super) chunk: Option<Bytes<Retained>>,
    pub(super) keep_reading: bool,
    pub(super) ok: bool,
}

pub(super) struct Staged<'a, S: Session> {
    state: &'a mut State<S>,
}

impl<'a, S: Session> Staged<'a, S> {
    pub(super) fn new(state: &'a mut State<S>) -> Self {
        Self { state }
    }

    pub(super) fn read(
        &mut self,
        bytes: &[u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
        receive: &mut impl FnMut(&[u8]),
    ) -> Result<(), Error> {
        let mut rest = bytes;
        loop {
            let take = self
                .state
                .buffers
                .append_recv(rest)
                .map_err(|_| Error::ReceiveOverflow)?;
            rest = &rest[take..];
            while self.consume_one_record(read, receive)? {}
            if rest.is_empty() {
                return Ok(());
            }
            if take == 0 {
                return Err(Error::Record(RecordError::BodyTooLarge));
            }
        }
    }

    pub(super) fn read_one_wire(
        &mut self,
        bytes: &[u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> WireRead {
        match self.read_one_wire_result(bytes, read) {
            Ok((consumed, chunk, keep_reading)) => WireRead {
                consumed,
                chunk,
                keep_reading,
                ok: true,
            },
            Err(_) => WireRead {
                consumed: bytes.len(),
                chunk: None,
                keep_reading: false,
                ok: false,
            },
        }
    }

    fn read_one_wire_result(
        &mut self,
        bytes: &[u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<(usize, Option<Bytes<Retained>>, bool), Error> {
        let mut consumed = 0;
        if self.state.buffers.recv().len() < HEADER_LEN {
            let needed = HEADER_LEN - self.state.buffers.recv().len();
            let take = needed.min(bytes.len());
            self.state
                .buffers
                .append_recv(&bytes[..take])
                .map_err(|_| Error::ReceiveOverflow)?;
            consumed += take;
            if self.state.buffers.recv().len() < HEADER_LEN {
                return Ok((consumed, None, true));
            }
        }
        let Some(frame) = RecordFrame::parse(self.state.buffers.recv())? else {
            return Ok((consumed, None, true));
        };
        let total = frame.len();
        if self.state.buffers.recv().len() < total {
            let needed = total - self.state.buffers.recv().len();
            let take = needed.min(bytes.len() - consumed);
            self.state
                .buffers
                .append_recv(&bytes[consumed..consumed + take])
                .map_err(|_| Error::ReceiveOverflow)?;
            consumed += take;
            if self.state.buffers.recv().len() < total {
                return Ok((consumed, None, true));
            }
        }
        let action = self.handle_record(total, read)?;
        let (chunk, keep_reading) = self.finish_wire_record(total, action)?;
        Ok((consumed, chunk, keep_reading))
    }

    fn consume_one_record(
        &mut self,
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
        receive: &mut impl FnMut(&[u8]),
    ) -> Result<bool, Error> {
        if self.state.is_closed() {
            return Ok(false);
        }
        let Some(frame) = RecordFrame::complete(self.state.buffers.recv())? else {
            return Ok(false);
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
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<RecordAction, Error> {
        let State {
            record: state,
            phase,
            buffers,
            peer_close,
        } = &mut *self.state;
        let (record, pending) = buffers.recv_record_and_pending(total)?;
        state.handle::<ReportFailure>(phase, peer_close, pending, record, read)
    }

    fn finish_record(
        &mut self,
        total: usize,
        action: RecordAction,
        receive: &mut impl FnMut(&[u8]),
    ) -> Result<bool, Error> {
        let keep_reading = match action {
            RecordAction::Application(plaintext_len) => {
                let range = HEADER_LEN..HEADER_LEN + plaintext_len;
                if !range.is_empty() {
                    receive(&self.state.buffers.recv()[range]);
                }
                true
            }
            RecordAction::Control(keep_reading) => keep_reading,
        };
        if !self.state.buffers.try_consume_recv(total) {
            return Err(Error::InvalidBufferProgress);
        }
        Ok(keep_reading)
    }

    fn finish_wire_record(
        &mut self,
        total: usize,
        action: RecordAction,
    ) -> Result<(Option<Bytes<Retained>>, bool), Error> {
        match action {
            RecordAction::Application(plaintext_len) => {
                let range = HEADER_LEN..HEADER_LEN + plaintext_len;
                let empty = range.is_empty();
                let Some(chunk) = self.state.buffers.take_recv_range(range) else {
                    return self.state.fatal_overflow().map(|keep| (None, keep));
                };
                Ok(((!empty).then_some(chunk), true))
            }
            RecordAction::Control(keep_reading) => {
                if !self.state.buffers.try_consume_recv(total) {
                    return Err(Error::InvalidBufferProgress);
                }
                Ok((None, keep_reading))
            }
        }
    }
}
