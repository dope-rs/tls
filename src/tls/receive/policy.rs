use crate::error;
use crate::state::buffers;
use crate::tls::{
    self, endpoint,
    receive::{Ingress, waiters},
    roles,
};
use dope::core::driver::{
    receive::credit,
    route::{self, table::conn},
};
use dope::net::wire::{receive::reserve, send, terminal};
use o3::depot::queue::tagged::entry;
use std::marker;

pub struct Blocked<'a, 'd, ID: route::Identity> {
    waiters: &'a mut waiters::Queue<'d, ID>,
    kind: waiters::Resource,
}
pub struct Policy<R>(marker::PhantomData<fn() -> R>);

/// Holds the admitted receive slot and any handshake output loan through processing.
pub struct Transaction<
    'a,
    'w,
    'd,
    R: roles::Protocol + 'w,
    ID: route::Identity + 'w,
    S = buffers::Reserve<'w>,
> where
    'd: 'w,
{
    wire: &'a mut tls::Connection<'w, R, ID>,
    send: Option<tls::Buffered<'a, 'w>>,
    run: &'a mut endpoint::Runtime<'w, 'd, R, ID>,
    recv: S,
}

impl<'a, 'w, 'd, R: roles::Protocol + 'w, ID: route::Identity + 'w> Transaction<'a, 'w, 'd, R, ID>
where
    'd: 'w,
{
    pub(in crate::tls) fn read<T>(
        self,
        read: impl FnOnce(Ingress<'_, 'w, R, ID>) -> (T, Result<(), error::Error>, buffers::Release),
    ) -> (
        Transaction<'a, 'w, 'd, R, ID, buffers::Release>,
        T,
        Result<(), error::Error>,
    ) {
        let Self {
            wire,
            send,
            run,
            recv,
        } = self;
        let (output, result, recv) = read(Ingress::new(wire, recv));
        (
            Transaction {
                wire,
                send,
                run,
                recv,
            },
            output,
            result,
        )
    }
}

impl<'w, 'd, R: roles::Protocol + 'w, ID: route::Identity + 'w>
    Transaction<'_, 'w, 'd, R, ID, buffers::Release>
where
    'd: 'w,
{
    pub(in crate::tls) fn is_peer_done(&self) -> bool {
        self.wire.peer_closed
    }

    pub(in crate::tls) fn finish(&mut self) -> Result<(), error::Error> {
        if let Some(send) = self.send.as_mut() {
            self.wire.emit_into(send.buffer_mut())?;
        }
        Ok(())
    }
}

impl<'w, 'd, R: roles::Protocol + 'w, ID: route::Identity + 'w, S> Transaction<'_, 'w, 'd, R, ID, S>
where
    'd: 'w,
{
    fn release(self, recv: buffers::Release) {
        drop(self.recv);
        if recv == buffers::Release::Released {
            self.run.waiters.wake(waiters::Resource::Recv);
        }
        if self
            .send
            .is_some_and(|send| send.complete() == send::Availability::Released)
        {
            self.run.waiters.wake(waiters::Resource::HandshakeEgress);
        }
    }
}

impl<'w, 'd, R: roles::Protocol + 'w, ID: route::Identity + 'w> reserve::Completion
    for Transaction<'_, 'w, 'd, R, ID>
where
    'd: 'w,
{
    fn complete(self) {
        self.release(buffers::Release::Released);
    }
}

impl<'w, 'd, R: roles::Protocol + 'w, ID: route::Identity + 'w> reserve::Completion
    for Transaction<'_, 'w, 'd, R, ID, buffers::Release>
where
    'd: 'w,
{
    fn complete(self) {
        let recv = self.recv;
        self.release(recv);
    }
}
impl<R: roles::Protocol> reserve::Try<tls::Tls<R>> for Policy<R> {
    type Block<'a, 'w, 'd, ID: route::Identity + 'w>
        = Blocked<'a, 'd, ID>
    where
        tls::Tls<R>: 'w,
        'd: 'w,
        'w: 'a;
    type Transaction<'a, 'w, 'd, ID: route::Identity + 'w>
        = Transaction<'a, 'w, 'd, R, ID>
    where
        tls::Tls<R>: 'w,
        'd: 'w,
        'w: 'a;

    /// Submitted ciphertext keeps its send owner until completion; receiving
    /// defers new native TLS output to after_send, preserving wire order.
    fn try_reserve<'a, 'w, 'd, ID: route::Identity + 'w>(
        wire: &'a mut tls::Connection<'w, R, ID>,
        send: Option<&'a mut tls::SendState<'w>>,
        run: &'a mut endpoint::Runtime<'w, 'd, R, ID>,
    ) -> reserve::Outcome<
        Self::Transaction<'a, 'w, 'd, ID>,
        Self::Block<'a, 'w, 'd, ID>,
        terminal::Error<'w, tls::Tls<R>>,
    >
    where
        tls::Tls<R>: 'w,
        'd: 'w,
        'w: 'a,
    {
        let open = wire.native.is_handshaking() && !wire.send_inflight;
        let recv = match wire.buffers.try_reserve() {
            Ok(Some(recv)) => recv,
            Ok(None) => {
                return reserve::Outcome::Blocked(Blocked {
                    waiters: &mut run.waiters,
                    kind: waiters::Resource::Recv,
                });
            }
            Err(cause) => {
                wire.failed = true;
                return reserve::Outcome::Failed(terminal::Error::from_cause(
                    error::Error::Allocation(cause.into()),
                ));
            }
        };
        let (true, Some(send)) = (open, send) else {
            return reserve::Outcome::Ready(Transaction {
                wire,
                send: None,
                run,
                recv,
            });
        };
        let Some(send) = send.reserve(wire.buffers.send_pool()) else {
            drop(recv);
            run.waiters.wake(waiters::Resource::Recv);
            return reserve::Outcome::Blocked(Blocked {
                waiters: &mut run.waiters,
                kind: waiters::Resource::HandshakeEgress,
            });
        };
        reserve::Outcome::Ready(Transaction {
            wire,
            send: Some(send),
            run,
            recv,
        })
    }
    fn cancel<'w, 'd, ID: route::Identity + 'w>(
        run: &mut endpoint::Runtime<'w, 'd, R, ID>,
        target: credit::Id<'d, ID>,
    ) where
        tls::Tls<R>: 'w,
        'd: 'w,
    {
        run.waiters.cancel(target);
    }
    fn release_recv<'w, 'd, ID: route::Identity + 'w>(run: &mut endpoint::Runtime<'w, 'd, R, ID>)
    where
        tls::Tls<R>: 'w,
        'd: 'w,
    {
        run.waiters.wake(waiters::Resource::Recv);
    }
    fn release_send<'w, 'd, ID: route::Identity + 'w>(run: &mut endpoint::Runtime<'w, 'd, R, ID>)
    where
        tls::Tls<R>: 'w,
        'd: 'w,
    {
        run.waiters.wake(waiters::Resource::HandshakeEgress);
    }
}
impl<'a, 'd, R: roles::Protocol, ID: route::Identity> reserve::Wait<'d, ID, tls::Tls<R>>
    for Blocked<'a, 'd, ID>
{
    type Registration = waiters::Registration<'a, 'd, ID>;
    fn register(
        self,
        credit: credit::Pending<'d, ID>,
    ) -> Result<Self::Registration, entry::Error<conn::Capacity>> {
        self.waiters.register(self.kind, credit)
    }
}
