use std::marker;

use dope::core::io::recv;
use dope::net::wire::{self, batch, receive};

use crate::state;
use crate::state::api::capabilities::Status as _;
use crate::tls::{self, endpoints, receive::waiters, roles};
use crate::transmissions;

pub struct Blocked<'a, 'd, R: roles::Protocol, const ID: u8> {
    runtime: &'a mut endpoints::Runtime<'d, R, ID>,
    resource: waiters::Resource,
}

pub struct Policy<R>(marker::PhantomData<fn() -> R>);

pub enum Transaction<'a, 'd, R: roles::Protocol, const ID: u8> {
    Handshake(Handshake<'a, 'd, R, ID>),
    Established(Established<'a, 'd, R, ID>),
}

pub struct Handshake<'a, 'd, R: roles::Protocol, const ID: u8> {
    wire: &'a mut tls::Connection<'d, R, ID>,
    send: &'a mut tls::SendState<'d>,
    runtime: &'a mut endpoints::Runtime<'d, R, ID>,
}

pub struct Established<'a, 'd, R: roles::Protocol, const ID: u8> {
    wire: &'a mut tls::Connection<'d, R, ID>,
    runtime: &'a mut endpoints::Runtime<'d, R, ID>,
}

impl<R: roles::Protocol> receive::Strategy<tls::Tls<R>> for Policy<R> {
    type Block<'a, 'd, const ID: u8>
        = Blocked<'a, 'd, R, ID>
    where
        R: 'd,
        'd: 'a;
    type Transaction<'a, 'd, const ID: u8>
        = Transaction<'a, 'd, R, ID>
    where
        R: 'd,
        'd: 'a;

    const BACKPRESSURE: bool = true;

    fn reserve<'a, 'd, const ID: u8>(
        wire: &'a mut tls::Connection<'d, R, ID>,
        send: &'a mut tls::SendState<'d>,
        runtime: &'a mut endpoints::Runtime<'d, R, ID>,
    ) -> Result<Self::Transaction<'a, 'd, ID>, Self::Block<'a, 'd, ID>>
    where
        R: 'd,
        'd: 'a,
    {
        let handshaking = wire.state.tls.is_handshaking();
        if handshaking && wire.send_inflight {
            return Err(Blocked {
                runtime,
                resource: waiters::Resource::HandshakeEgress,
            });
        }
        if !state::Internals::reserve_recv_buffer(&mut wire.state.tls) {
            return Err(Blocked {
                runtime,
                resource: waiters::Resource::Recv,
            });
        }
        if !handshaking {
            return Ok(Transaction::Established(Established { wire, runtime }));
        }
        let send_pool = state::Internals::pending_pool(&wire.state.tls);
        if !send.reserve(send_pool) {
            if state::Internals::release_empty_recv_buffer(&mut wire.state.tls) {
                runtime.waiters.wake(waiters::Resource::Recv);
            }
            return Err(Blocked {
                runtime,
                resource: waiters::Resource::HandshakeEgress,
            });
        }

        state::Internals::swap_pending_buffer(&mut wire.state.tls, &mut send.buffer);
        Ok(Transaction::Handshake(Handshake {
            wire,
            send,
            runtime,
        }))
    }

    fn cancel<'d, const ID: u8>(
        runtime: &mut endpoints::Runtime<'d, R, ID>,
        target: wire::RecvCreditId<'d, ID>,
    ) where
        R: 'd,
    {
        runtime.waiters.cancel(target);
    }

    fn recv_released<'d, const ID: u8>(runtime: &mut endpoints::Runtime<'d, R, ID>)
    where
        R: 'd,
    {
        runtime.waiters.wake(waiters::Resource::Recv);
    }

    fn send_released<'d, const ID: u8>(runtime: &mut endpoints::Runtime<'d, R, ID>)
    where
        R: 'd,
    {
        runtime.waiters.wake(waiters::Resource::HandshakeEgress);
    }
}

impl<'a, 'd, R: roles::Protocol + 'd, const ID: u8> receive::Wait<'d, ID, tls::Tls<R>>
    for Blocked<'a, 'd, R, ID>
{
    type Registration = waiters::Registration<'a, 'd, ID>;

    fn register(self, credit: wire::RecvCredit<'d, ID>) -> Option<Self::Registration> {
        self.runtime.waiters.register(self.resource, credit)
    }
}

impl<'d, R: roles::Protocol, const ID: u8> receive::Transaction<'d, tls::Tls<R>>
    for Transaction<'_, 'd, R, ID>
{
    fn process<'bytes>(
        &mut self,
        bytes: &'bytes mut [u8],
        capacity: &batch::Capacity<tls::Tls<R>>,
    ) -> <tls::Tls<R> as wire::Wire>::RecvBatch<'bytes>
    where
        'd: 'bytes,
    {
        match self {
            Self::Handshake(transaction) => <tls::Tls<R> as wire::Wire>::process_recv(
                transaction.wire,
                transaction.runtime,
                bytes,
                capacity,
            ),
            Self::Established(transaction) => <tls::Tls<R> as wire::Wire>::process_recv(
                transaction.wire,
                transaction.runtime,
                bytes,
                capacity,
            ),
        }
    }

    fn process_retained<'bytes>(
        &mut self,
        bytes: recv::Lease<'bytes>,
    ) -> Option<<tls::Tls<R> as wire::Wire>::RetainedRecv<'bytes>>
    where
        'd: 'bytes,
    {
        match self {
            Self::Handshake(transaction) => <tls::Tls<R> as wire::Wire>::process_retained_recv(
                transaction.wire,
                transaction.runtime,
                bytes,
            ),
            Self::Established(transaction) => <tls::Tls<R> as wire::Wire>::process_retained_recv(
                transaction.wire,
                transaction.runtime,
                bytes,
            ),
        }
    }
}

impl<R: roles::Protocol, const ID: u8> Drop for Transaction<'_, '_, R, ID> {
    fn drop(&mut self) {
        match self {
            Self::Handshake(transaction) => {
                state::Internals::swap_pending_buffer(
                    &mut transaction.wire.state.tls,
                    &mut transaction.send.buffer,
                );
                let recv =
                    state::Internals::release_empty_recv_buffer(&mut transaction.wire.state.tls);
                let send =
                    transmissions::SendBuffer::release_if_empty(transaction.send).is_released();
                if recv {
                    transaction.runtime.waiters.wake(waiters::Resource::Recv);
                }
                if send {
                    transaction
                        .runtime
                        .waiters
                        .wake(waiters::Resource::HandshakeEgress);
                }
            }
            Self::Established(transaction) => {
                if state::Internals::release_empty_recv_buffer(&mut transaction.wire.state.tls) {
                    transaction.runtime.waiters.wake(waiters::Resource::Recv);
                }
            }
        }
    }
}
