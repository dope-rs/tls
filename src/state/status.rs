use shin::alert::AlertDescription;

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
    Fatal(AlertDescription),
    Truncated,
}
