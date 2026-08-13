use crate::state::{self, sessions};

pub(super) struct ConnectionState<'d, S: sessions::Peer> {
    pub(super) tls: state::State<'d, S>,
    pub(super) close: bool,
    pub(super) close_notify_sent: bool,
}

impl<'d, S: sessions::Peer> ConnectionState<'d, S> {
    pub(super) fn new(tls: state::State<'d, S>) -> Self {
        Self {
            tls,
            close: false,
            close_notify_sent: false,
        }
    }
}
