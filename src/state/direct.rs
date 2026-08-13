use std::{mem, num};

use shin::{connection, wire::record};

use crate::state::api::capabilities::Status as _;
use crate::state::records::events;
use crate::state::{self, records, sessions, status};

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
        while self.offset < self.layout.scan_end {
            let offset = self.offset;
            let header = self.bytes.get(offset..offset + record::HEADER_LEN)?;
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            self.offset = offset + record::HEADER_LEN + body_len;
            if header[0] != CHUNK_APPLICATION {
                continue;
            }
            let plaintext_len = u16::from_be_bytes([header[1], header[2]]) as usize;
            self.remaining -= 1;
            return self
                .bytes
                .get(offset + record::HEADER_LEN..offset + record::HEADER_LEN + plaintext_len);
        }
        if self.offset == self.layout.scan_end && self.layout.tail_end != 0 {
            let start = self.layout.scan_end + record::HEADER_LEN;
            self.offset = self.layout.tail_end;
            self.remaining -= 1;
            return self.bytes.get(start..self.layout.tail_end);
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

#[doc(hidden)]
#[must_use]
pub struct WireRead<'a> {
    plain: PlainChunks<'a>,
    status: status::Read,
}

const _: () =
    assert!(mem::size_of::<WireRead<'static>>() <= mem::size_of::<(PlainChunks<'static>, bool)>());

impl<'a> WireRead<'a> {
    fn new(plain: PlainChunks<'a>, status: status::Read) -> Self {
        Self { plain, status }
    }

    pub fn status(&self) -> status::Read {
        self.status
    }

    pub fn into_plain(self) -> PlainChunks<'a> {
        self.plain
    }

    pub(crate) fn fail(&mut self) {
        self.status = status::Read::Failed;
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PlainLayout {
    scan_end: usize,
    tail_end: usize,
    chunks: usize,
    plain_len: usize,
}

impl PlainLayout {
    fn segmented(end: usize, chunks: usize, plain_len: usize) -> Self {
        Self {
            scan_end: end,
            tail_end: 0,
            chunks,
            plain_len,
        }
    }

    fn empty() -> Self {
        Self::segmented(0, 0, 0)
    }

    fn bounded(self, bytes: &mut [u8], limit: num::NonZeroUsize) -> Result<Self, ()> {
        if self.chunks <= limit.get() {
            return Ok(self);
        }
        let tail_record = self.tail_record(bytes, limit.get() - 1).ok_or(())?;
        let tail_end = self.compact_tail(bytes, tail_record).ok_or(())?;
        Ok(Self {
            scan_end: tail_record,
            tail_end,
            chunks: limit.get(),
            plain_len: self.plain_len,
        })
    }

    fn tail_record(&self, bytes: &[u8], prefix_chunks: usize) -> Option<usize> {
        let mut offset = 0;
        let mut chunks = 0;
        while offset < self.scan_end {
            let header = bytes.get(offset..offset.checked_add(record::HEADER_LEN)?)?;
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if header[0] == CHUNK_APPLICATION {
                let plain_len = u16::from_be_bytes([header[1], header[2]]) as usize;
                if plain_len != 0 {
                    if chunks == prefix_chunks {
                        return Some(offset);
                    }
                    chunks += 1;
                }
            }
            offset = offset.checked_add(record::HEADER_LEN + body_len)?;
        }
        None
    }

    fn compact_tail(&self, bytes: &mut [u8], tail_record: usize) -> Option<usize> {
        let mut read = tail_record;
        let mut write = tail_record.checked_add(record::HEADER_LEN)?;
        while read < self.scan_end {
            let header_end = read.checked_add(record::HEADER_LEN)?;
            let header = bytes.get(read..header_end)?;
            let application = header[0] == CHUNK_APPLICATION;
            let plain_len = u16::from_be_bytes([header[1], header[2]]) as usize;
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let next = header_end.checked_add(body_len)?;
            if next > self.scan_end {
                return None;
            }
            if application && plain_len != 0 {
                let source_end = header_end.checked_add(plain_len)?;
                let destination_end = write.checked_add(plain_len)?;
                if source_end > next || destination_end > bytes.len() {
                    return None;
                }
                bytes.copy_within(header_end..source_end, write);
                write = destination_end;
            }
            read = next;
        }
        Some(write)
    }

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

    fn current(&self, bytes: &[u8]) -> Option<(usize, usize, usize, usize)> {
        let mut offset = self.record_offset;
        while offset < self.layout.scan_end {
            let header = bytes.get(offset..offset + record::HEADER_LEN)?;
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let total = record::HEADER_LEN + body_len;
            if header[0] != CHUNK_APPLICATION {
                offset += total;
                continue;
            }
            let plain_len = u16::from_be_bytes([header[1], header[2]]) as usize;
            let plain_offset = if offset == self.record_offset {
                self.plain_offset
            } else {
                0
            };
            if plain_offset == plain_len {
                offset += total;
                continue;
            }
            return Some((offset, plain_offset, plain_len, total));
        }
        if offset == self.layout.scan_end && self.layout.tail_end != 0 {
            let plain_len = self
                .layout
                .tail_end
                .checked_sub(offset + record::HEADER_LEN)?;
            if self.plain_offset == plain_len {
                return None;
            }
            return Some((
                offset,
                self.plain_offset,
                plain_len,
                self.layout.tail_end - offset,
            ));
        }
        None
    }

    pub(crate) fn chunk<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let Some((record_offset, plain_offset, plain_len, _)) = self.current(bytes) else {
            return &[];
        };
        let start = record_offset + record::HEADER_LEN + plain_offset;
        bytes
            .get(start..start + plain_len - plain_offset)
            .unwrap_or(&[])
    }

    pub(crate) fn consume(&mut self, bytes: &[u8], requested: usize) -> usize {
        let Some((record_offset, plain_offset, plain_len, total)) = self.current(bytes) else {
            return 0;
        };
        let consumed = requested.min(plain_len - plain_offset);
        if consumed == 0 {
            return 0;
        }
        let next = plain_offset + consumed;
        if next == plain_len {
            self.record_offset = record_offset + total;
            self.plain_offset = 0;
        } else {
            self.record_offset = record_offset;
            self.plain_offset = next;
        }
        self.remaining -= consumed;
        consumed
    }
}

pub(crate) struct Reader<'a, 'd, S: sessions::Peer> {
    state: &'a mut state::State<'d, S>,
}

impl<'a, 'd, S: sessions::Peer> Reader<'a, 'd, S> {
    pub(crate) fn new(state: &'a mut state::State<'d, S>) -> Self {
        Self { state }
    }

    pub(crate) fn read_in_place<'b>(
        &mut self,
        bytes: &'b mut [u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
    ) -> WireRead<'b> {
        self.read_in_place_with_limit(bytes, None, read)
    }

    pub(crate) fn read_batch_in_place<'b>(
        &mut self,
        bytes: &'b mut [u8],
        limit: num::NonZeroUsize,
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
    ) -> WireRead<'b> {
        self.read_in_place_with_limit(bytes, Some(limit), read)
    }

    fn read_in_place_with_limit<'b>(
        &mut self,
        bytes: &'b mut [u8],
        limit: Option<num::NonZeroUsize>,
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
    ) -> WireRead<'b> {
        debug_assert!(!self.state.has_staged_recv());
        let mut offset = 0;
        let mut chunks = 0;
        let mut plain_len = 0;
        let mut status = if self.state.is_closed() {
            status::Read::Stop
        } else {
            status::Read::Continue
        };
        while offset < bytes.len() && !self.state.is_closed() {
            let total = match records::RecordFrame::complete(&bytes[offset..]) {
                Ok(Some(frame)) => frame.len(),
                Ok(None) => {
                    status = match self.state.buffers.append_recv(&bytes[offset..]) {
                        Ok(consumed) if consumed == bytes.len() - offset => status::Read::Stop,
                        Ok(_) | Err(_) => status::Read::Failed,
                    };
                    break;
                }
                Err(_) => {
                    status = status::Read::Failed;
                    break;
                }
            };
            let record = &mut bytes[offset..offset + total];
            let action = match self.handle_record_in_place(record, read) {
                Ok(action) => action,
                Err(()) => {
                    status = status::Read::Failed;
                    break;
                }
            };
            status = match action {
                records::RecordAction::Application(plaintext_len) => {
                    record[0] = CHUNK_APPLICATION;
                    record[1..3].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
                    chunks += usize::from(plaintext_len != 0);
                    plain_len += plaintext_len;
                    status::Read::Continue
                }
                records::RecordAction::Control(control) => {
                    record[0] = CHUNK_SKIP;
                    record[1..3].fill(0);
                    control.status()
                }
            };
            offset += total;
            if status != status::Read::Continue {
                break;
            }
        }
        let layout = PlainLayout::segmented(offset, chunks, plain_len);
        let layout = if let Some(limit) = limit {
            match layout.bounded(bytes, limit) {
                Ok(layout) => layout,
                Err(()) => {
                    status = status::Read::Failed;
                    PlainLayout::empty()
                }
            }
        } else {
            layout
        };
        WireRead::new(PlainChunks::new(bytes, layout), status)
    }

    fn handle_record_in_place(
        &mut self,
        record: &mut [u8],
        read: &mut impl FnMut(
            &mut S,
            connection::Epoch,
            &[u8],
            &mut events::RecordEvents<'_, '_>,
        ) -> Result<(), connection::DriveError<records::RecordFailure>>,
    ) -> Result<records::RecordAction, ()> {
        let state::State {
            record: state,
            phase,
            buffers,
            control,
            peer_close,
        } = &mut *self.state;
        state.handle::<records::IgnoreFailure>(
            phase,
            peer_close,
            control,
            buffers.pending_output(),
            record,
            read,
        )
    }
}
