use crate::error;
use crate::tls::{self, connection, endpoints, roles};
use crate::{state, transmissions};

pub(super) struct Open<'a, 'd, R: roles::Protocol, const ID: u8> {
    runtime: &'a mut endpoints::Runtime<'d, R, ID>,
}

impl<'a, 'd, R: roles::Protocol, const ID: u8> Open<'a, 'd, R, ID> {
    pub(super) fn new(runtime: &'a mut endpoints::Runtime<'d, R, ID>) -> Self {
        Self { runtime }
    }

    pub(super) fn try_take(
        self,
    ) -> Result<Option<(tls::Connection<'d, R, ID>, tls::SendState<'d>)>, error::Error> {
        let tls = R::open::<ID>(
            &mut self.runtime.role,
            &self.runtime.buffers.recv,
            &self.runtime.buffers.send,
        )?;
        Ok(tls.map(|mut tls| {
            let mut send = tls::SendState::new();
            state::Internals::swap_pending_buffer(&mut tls, &mut send.buffer);
            let _ = transmissions::SendBuffer::release_if_empty(&mut send);
            (
                tls::Connection {
                    state: connection::ConnectionState::new(tls),
                    send_inflight: false,
                },
                send,
            )
        }))
    }
}
