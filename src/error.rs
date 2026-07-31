use std::{error, fmt, io};

use shin::connection;
use shin::wire::{
    alert::AlertDescription,
    record::{RecordError, RecordKeyError},
};

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Handshake(connection::Error),
    Record(RecordError),
    RecordKey(RecordKeyError),
    UnexpectedRecord,
    NotEstablished,
    Io(io::Error),
    PeerAlert(AlertDescription),
    MalformedAlert,
    Truncated,
    ReceiveOverflow,
    SendOverflow,
    BufferUnavailable,
    InvalidBufferProgress,
    EarlyDataUnsupported,
}

impl From<RecordError> for Error {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl From<RecordKeyError> for Error {
    fn from(error: RecordKeyError) -> Self {
        Self::RecordKey(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnexpectedRecord, Self::UnexpectedRecord)
            | (Self::NotEstablished, Self::NotEstablished)
            | (Self::ReceiveOverflow, Self::ReceiveOverflow)
            | (Self::SendOverflow, Self::SendOverflow)
            | (Self::BufferUnavailable, Self::BufferUnavailable)
            | (Self::InvalidBufferProgress, Self::InvalidBufferProgress)
            | (Self::EarlyDataUnsupported, Self::EarlyDataUnsupported)
            | (Self::MalformedAlert, Self::MalformedAlert)
            | (Self::Truncated, Self::Truncated) => true,
            (Self::Handshake(a), Self::Handshake(b)) => a == b,
            (Self::Record(a), Self::Record(b)) => a == b,
            (Self::RecordKey(a), Self::RecordKey(b)) => a == b,
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (Self::PeerAlert(a), Self::PeerAlert(b)) => a == b,
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake(error) => write!(formatter, "TLS handshake failed: {error:?}"),
            Self::Record(error) => write!(formatter, "TLS record failed: {error:?}"),
            Self::RecordKey(error) => write!(formatter, "TLS record key failed: {error:?}"),
            Self::UnexpectedRecord => formatter.write_str("unexpected TLS record"),
            Self::NotEstablished => formatter.write_str("TLS connection is not established"),
            Self::Io(error) => error.fmt(formatter),
            Self::PeerAlert(alert) => write!(formatter, "peer sent fatal TLS alert: {alert:?}"),
            Self::MalformedAlert => formatter.write_str("malformed TLS alert"),
            Self::Truncated => formatter.write_str("TLS connection closed without close_notify"),
            Self::ReceiveOverflow => formatter.write_str("TLS receive buffer overflow"),
            Self::SendOverflow => formatter.write_str("TLS send buffer overflow"),
            Self::BufferUnavailable => formatter.write_str("TLS buffer unavailable"),
            Self::InvalidBufferProgress => formatter.write_str("invalid TLS buffer progress"),
            Self::EarlyDataUnsupported => formatter.write_str("TLS early data is unsupported"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
