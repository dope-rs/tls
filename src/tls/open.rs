use super::{ConnectionState, Role, Runtime, SendState, TlsConnection};

pub(super) struct Open<'a, 'd, R: Role> {
    runtime: &'a mut Runtime<'d, R>,
}

impl<'a, 'd, R: Role> Open<'a, 'd, R> {
    pub(super) fn new(runtime: &'a mut Runtime<'d, R>) -> Self {
        Self { runtime }
    }

    pub(super) fn take(self) -> Option<(TlsConnection<'d, R>, SendState)> {
        let send = SendState::new(self.runtime.buffers.send.clone());
        let tls = R::open(
            &mut self.runtime.role,
            self.runtime.buffers.recv.clone(),
            self.runtime.buffers.pending.clone(),
        )?;
        Some((
            TlsConnection {
                state: ConnectionState::new(tls),
                send_inflight: false,
            },
            send,
        ))
    }
}
