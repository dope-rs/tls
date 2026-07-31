use dope_net::wire::RecvTarget;
use shin::connection::{DriveError, Epoch};
use shin::wire::record::HEADER_LEN;

use super::State;
use super::record::{IgnoreFailure, RecordAction, RecordEvents, RecordFailure, RecordFrame};
use super::sessions::Session;

const CHUNK_SKIP: u8 = 0;
const CHUNK_APPLICATION: u8 = 1;

#[doc(hidden)]
pub struct PlainChunks<'a> {
    bytes: &'a [u8],
    offset: usize,
    layout: PlainLayout,
    remaining: usize,
}

impl<'a> PlainChunks<'a> {
    fn new(bytes: &'a [u8], layout: PlainLayout) -> Self {
        Self {
            bytes,
            offset: 0,
            remaining: layout.chunks,
            layout,
        }
    }

    pub(crate) fn into_layout(self) -> PlainLayout {
        debug_assert_eq!(self.offset, 0);
        self.layout
    }
}

impl<'a> Iterator for PlainChunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.layout.end {
            let offset = self.offset;
            let header = self.bytes.get(offset..offset + HEADER_LEN)?;
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            self.offset = offset + HEADER_LEN + body_len;
            if header[0] != CHUNK_APPLICATION {
                continue;
            }
            let plaintext_len = u16::from_be_bytes([header[1], header[2]]) as usize;
            self.remaining -= 1;
            return self
                .bytes
                .get(offset + HEADER_LEN..offset + HEADER_LEN + plaintext_len);
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for PlainChunks<'_> {
    fn len(&self) -> usize {
        self.remaining
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PlainLayout {
    end: usize,
    chunks: usize,
    plain_len: usize,
}

impl PlainLayout {
    pub(crate) fn plain_len(self) -> usize {
        self.plain_len
    }

    pub(crate) fn cursor(self) -> PlainCursor {
        PlainCursor {
            layout: self,
            record_offset: 0,
            plain_offset: 0,
            remaining: self.plain_len,
        }
    }
}

pub(crate) struct PlainCursor {
    layout: PlainLayout,
    record_offset: usize,
    plain_offset: usize,
    remaining: usize,
}

impl PlainCursor {
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }

    pub(crate) fn read_into(&mut self, bytes: &[u8], target: &mut RecvTarget<'_>) {
        let initial = target.len();
        let expected = target.remaining().min(self.remaining);
        while target.len() - initial < expected && self.record_offset < self.layout.end {
            let offset = self.record_offset;
            let Some(header) = bytes.get(offset..offset + HEADER_LEN) else {
                break;
            };
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let total = HEADER_LEN + body_len;
            if header[0] != CHUNK_APPLICATION {
                self.record_offset += total;
                self.plain_offset = 0;
                continue;
            }
            let plain_len = u16::from_be_bytes([header[1], header[2]]) as usize;
            if self.plain_offset == plain_len {
                self.record_offset += total;
                self.plain_offset = 0;
                continue;
            }
            let written = target.len() - initial;
            let take = (expected - written).min(plain_len - self.plain_offset);
            let start = offset + HEADER_LEN + self.plain_offset;
            let Some(source) = bytes.get(start..start + take) else {
                break;
            };
            let written = target.write_prefix(source);
            debug_assert_eq!(written, take);
            self.plain_offset += take;
        }
        let written = target.len() - initial;
        self.remaining -= written;
    }
}

pub(super) struct Direct<'a, S: Session> {
    state: &'a mut State<S>,
}

impl<'a, S: Session> Direct<'a, S> {
    pub(super) fn new(state: &'a mut State<S>) -> Self {
        Self { state }
    }

    pub(super) fn read_in_place<'b>(
        &mut self,
        bytes: &'b mut [u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> (PlainChunks<'b>, bool) {
        debug_assert!(!self.state.has_staged_recv());
        let mut offset = 0;
        let mut chunks = 0;
        let mut plain_len = 0;
        let mut ok = true;
        while offset < bytes.len() && !self.state.is_closed() {
            let total = match RecordFrame::complete(&bytes[offset..]) {
                Ok(Some(frame)) => frame.len(),
                Ok(None) => {
                    ok = match self.state.buffers.append_recv(&bytes[offset..]) {
                        Ok(consumed) => consumed == bytes.len() - offset,
                        Err(_) => false,
                    };
                    break;
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            };
            let record = &mut bytes[offset..offset + total];
            let action = match self.handle_record_in_place(record, read) {
                Ok(action) => action,
                Err(()) => {
                    ok = false;
                    break;
                }
            };
            let keep_reading = match action {
                RecordAction::Application(plaintext_len) => {
                    record[0] = CHUNK_APPLICATION;
                    record[1..3].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
                    chunks += usize::from(plaintext_len != 0);
                    plain_len += plaintext_len;
                    true
                }
                RecordAction::Control(keep_reading) => {
                    record[0] = CHUNK_SKIP;
                    record[1..3].fill(0);
                    keep_reading
                }
            };
            offset += total;
            if !keep_reading {
                break;
            }
        }
        (
            PlainChunks::new(
                bytes,
                PlainLayout {
                    end: offset,
                    chunks,
                    plain_len,
                },
            ),
            ok,
        )
    }

    fn handle_record_in_place(
        &mut self,
        record: &mut [u8],
        read: &mut impl FnMut(
            &mut S,
            Epoch,
            &[u8],
            &mut RecordEvents<'_>,
        ) -> Result<(), DriveError<RecordFailure>>,
    ) -> Result<RecordAction, ()> {
        let State {
            record: state,
            phase,
            buffers,
            peer_close,
        } = &mut *self.state;
        state.handle::<IgnoreFailure>(phase, peer_close, buffers.pending_output(), record, read)
    }
}
