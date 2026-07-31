use crate::state::State;
use crate::state::sessions::Session;

pub(super) struct ConnectionState<S: Session> {
    pub(super) tls: State<S>,
    pub(super) close: bool,
    pub(super) close_notify_sent: bool,
}

impl<S: Session> ConnectionState<S> {
    pub(super) fn new(tls: State<S>) -> Self {
        Self {
            tls,
            close: false,
            close_notify_sent: false,
        }
    }
}
