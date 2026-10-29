use std::io;

use dope::net;
use o3::{alloc, base::num::bounded, buffer::write::consume};

#[derive(Debug)]
pub enum Error {
    Tls(rustls::Error),
    Io(io::Error),
    Allocation(alloc::Error),
    Staged(bounded::Error),
    Retained(bounded::Error),
    BufferUnavailable,
    InvalidBufferProgress,
    Consume {
        buffer: net::BufferKind,
        cause: consume::Error,
    },
}

impl From<rustls::Error> for Error {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<alloc::Error> for Error {
    fn from(error: alloc::Error) -> Self {
        Self::Allocation(error)
    }
}

impl From<alloc::Exhausted> for Error {
    fn from(error: alloc::Exhausted) -> Self {
        Self::Allocation(error.into())
    }
}
