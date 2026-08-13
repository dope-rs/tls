use shin::wire::alert;

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Read {
    Continue,
    Stop,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Handshaking,
    Established,
    PeerClosed,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerClose {
    Open,
    CloseNotify,
    Fatal(alert::Description),
    Truncated,
}
