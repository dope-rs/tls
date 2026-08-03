use std::io::{self, Error, ErrorKind, IoSlice, Write};

use dope_net::wire::buffered::{Buffer, Scratch};
use dope_net::wire::send::SendStorage;
use rustls::Connection;

use crate::send::SendBuffer;

pub struct RustSendState(pub(super) Buffer<Scratch>);

// SAFETY: the fixed pool buffer mutates only through exclusive RustSendState access.
impl SendStorage for RustSendState {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl SendBuffer for RustSendState {
    fn buffer_mut(&mut self) -> Option<&mut Buffer<Scratch>> {
        Some(&mut self.0)
    }

    fn try_buffer(&mut self) -> Option<&mut Buffer<Scratch>> {
        Some(&mut self.0)
    }
}

pub(super) struct ConnectionState {
    pub(super) conn: Option<Connection>,
    pub(super) readable_plain: usize,
    pub(super) close: bool,
    pub(super) close_notify_sent: bool,
}

impl ConnectionState {
    pub(super) fn empty() -> Self {
        Self {
            conn: None,
            readable_plain: 0,
            close: false,
            close_notify_sent: false,
        }
    }
}

pub(super) struct CiphertextWriter<'a> {
    egress: &'a mut Buffer<Scratch>,
}

impl<'a> CiphertextWriter<'a> {
    pub(super) fn new(egress: &'a mut Buffer<Scratch>) -> Self {
        Self { egress }
    }

    pub(super) fn remaining(&self) -> usize {
        self.egress.spare_capacity()
    }
}

impl Write for CiphertextWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = self.remaining().min(bytes.len());
        if count == 0 {
            Err(Error::from(ErrorKind::WouldBlock))
        } else {
            self.egress
                .try_extend_from_slice(&bytes[..count])
                .map_err(|_| Error::from(ErrorKind::WouldBlock))?;
            Ok(count)
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut written = 0;
        let mut has_bytes = false;
        for bytes in bufs {
            if bytes.is_empty() {
                continue;
            }
            has_bytes = true;
            let count = self.remaining().min(bytes.len());
            if count == 0 {
                break;
            }
            self.egress
                .try_extend_from_slice(&bytes[..count])
                .map_err(|_| Error::from(ErrorKind::WouldBlock))?;
            written += count;
            if count != bytes.len() {
                break;
            }
        }
        if written == 0 && has_bytes {
            Err(Error::from(ErrorKind::WouldBlock))
        } else {
            Ok(written)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
