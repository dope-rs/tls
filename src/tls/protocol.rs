use dope::core::driver::route;
use std::marker;

use dope::core::{driver::route::table::conn, io::recv};
use dope::net::{
    self,
    wire::{self, domain, send, terminal},
};
use send::reclaim;

use crate::state::buffers;
use crate::tls;
use crate::tls::{
    endpoint,
    receive::{self, policy, waiters},
    roles, senders,
};

pub struct Bootstrap<R: roles::Protocol>(marker::PhantomData<fn() -> R>);

impl<R: roles::Protocol> domain::Allocate<tls::Tls<R>> for Bootstrap<R> {
    fn try_storage<ID: route::Identity>(
        cap: conn::Capacity,
    ) -> Result<endpoint::Sessions<R, ID>, net::Resource> {
        Ok(endpoint::Sessions::from_count(cap.entries()))
    }
}

impl<R: roles::Protocol> domain::Bootstrap<tls::Tls<R>> for Bootstrap<R> {
    fn try_runtime<'w, 'd, ID: route::Identity + 'w>(
        limits: domain::Limits,
        bound: endpoint::Bound<'w, R, ID>,
    ) -> Result<endpoint::Runtime<'w, 'd, R, ID>, net::Resource>
    where
        tls::Tls<R>: 'w,
        'd: 'w,
    {
        let layout = bound.plan.layout(limits)?;
        let endpoint::Bound {
            role,
            storage: store,
            ..
        } = bound;
        let (pools, waiters) = store.bind_pools(layout, || {
            waiters::Queue::try_new(limits.connections()).map_err(net::Resource::Queue)
        })?;
        Ok(endpoint::Runtime {
            pending: None,
            buffers: pools,
            waiters,
            role,
        })
    }
}

pub struct Ingress<R: roles::Protocol>(marker::PhantomData<fn() -> R>);

pub struct Egress<R: roles::Protocol>(marker::PhantomData<fn() -> R>);

impl<R: roles::Protocol> send::Policy<tls::Tls<R>> for Egress<R> {
    type Reclaim = reclaim::OnSubmit;

    fn has_capacity<'w, 'd: 'w, ID: route::Identity + 'w>(
        run: &endpoint::Runtime<'w, 'd, R, ID>,
    ) -> bool
    where
        tls::Tls<R>: 'w,
    {
        run.buffers.send.available() != 0
    }

    fn prepare<'a, 'd, ID: route::Identity + 'd>(
        context: send::Context<'a, 'd, ID, tls::Tls<R>, send::Storage<'a, tls::SendState<'d>>>,
        plain: send::Plain<'a>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Prepared<'a, Self::Reclaim, impl send::Payload<'a>>>
    where
        tls::Tls<R>: 'd,
        'd: 'a,
    {
        let (wire, send) = context.into_parts();
        let mut sender = senders::Sender::new(wire);
        sender.prepare(send, plain, end)
    }

    fn prepare_many<'a, 'd, ID: route::Identity + 'd, const N: usize>(
        context: send::Context<'a, 'd, ID, tls::Tls<R>, send::Storage<'a, tls::SendState<'d>>>,
        many: send::Vectored<'a, N>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Prepared<'a, Self::Reclaim, impl send::Payload<'a>>>
    where
        tls::Tls<R>: 'd,
        'd: 'a,
    {
        let (wire, send) = context.into_parts();
        let mut sender = senders::Sender::new(wire);
        sender.prepare_many(send, many, end)
    }

    fn after_send<'a, 'd, ID: route::Identity + 'd>(
        context: send::Context<
            'a,
            'd,
            ID,
            tls::Tls<R>,
            send::Completion<'a, Self::Reclaim, tls::SendState<'d>>,
        >,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Transition<'a, Self::Reclaim, impl send::Payload<'a>>>
    where
        tls::Tls<R>: 'd,
        'd: 'a,
    {
        let (wire, done) = context.into_parts();
        let mut sender = senders::Sender::new(wire);
        sender.after_send(done, end)
    }

    fn settle<'a, 'd, ID: route::Identity + 'd>(
        context: send::Context<
            'a,
            'd,
            ID,
            tls::Tls<R>,
            send::Completion<'a, Self::Reclaim, tls::SendState<'d>>,
        >,
        end: Option<terminal::Drain<'_, 'd, tls::Tls<R>>>,
    ) -> send::Transition<'a, Self::Reclaim, impl send::Payload<'a>>
    where
        tls::Tls<R>: 'd,
        'd: 'a,
    {
        let (wire, done) = context.into_parts();
        senders::Sender::new(wire).settle(done, end)
    }

    fn flush<'a, 'd, ID: route::Identity + 'd>(
        context: send::Context<'a, 'd, ID, tls::Tls<R>, send::Storage<'a, tls::SendState<'d>>>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Prepared<'a, Self::Reclaim, impl send::Payload<'a>>>
    where
        tls::Tls<R>: 'd,
        'd: 'a,
    {
        let (wire, send) = context.into_parts();
        let mut sender = senders::Sender::new(wire);
        sender.flush(send, end)
    }

    fn drain<'a, 'd, ID: route::Identity + 'd>(
        context: send::Context<'a, 'd, ID, tls::Tls<R>, send::Storage<'a, tls::SendState<'d>>>,
        end: Option<terminal::Drain<'_, 'd, tls::Tls<R>>>,
    ) -> send::Prepared<'a, Self::Reclaim, impl send::Payload<'a>>
    where
        tls::Tls<R>: 'd,
        'd: 'a,
    {
        let (wire, send) = context.into_parts();
        senders::Sender::new(wire).drain(send, end)
    }

    fn close<'a, 'd, ID: route::Identity + 'd>(
        context: send::Context<'a, 'd, ID, tls::Tls<R>, send::Storage<'a, tls::SendState<'d>>>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Prepared<'a, Self::Reclaim, impl send::Payload<'a>>>
    where
        tls::Tls<R>: 'd,
        'd: 'a,
    {
        let (wire, mut send) = context.into_parts();
        let Some(buffer) = wire.try_buffer(&mut send) else {
            return end.output(send.buffer_wait());
        };
        let result = wire.seal_close(buffer);
        send.drop_empty();
        let output = senders::Sender::new(wire).finish(send.consume_none(), result.is_err());
        match result {
            Err(cause) => end.terminal(
                output,
                terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
            ),
            Ok(()) => end.output(output),
        }
    }
}

const _: () = {
    use mode::access;
    use receive::stream;
    use reserve::Completion as _;
    use wire::receive::{Policy, batch, eof, mode, reserve};

    impl<R: roles::Protocol> Policy<tls::Tls<R>> for Ingress<R> {
        type Batch<'a>
            = receive::Batch<'a>
        where
            tls::Tls<R>: 'a;
        type Cursor<'w, 'd>
            = stream::Retained<'w, 'd>
        where
            tls::Tls<R>: 'w,
            'd: 'w;
        type Access = access::Segments;
        type Eof = eof::State;
        type Reserve = reserve::Waiting<policy::Policy<R>>;
        type Credit = mode::Enabled;
        /// Plaintext prefixes do not map back to encrypted receive prefixes.
        type Discard = mode::Disabled;

        fn process<'id, 'a, 'input, 'w, 'd, ID: route::Identity + 'w>(
            txn: policy::Transaction<'a, 'w, 'd, R, ID>,
            bytes: &'input mut [u8],
            cap: batch::Grant<'id, 'd, tls::Tls<R>>,
            end: terminal::Both<'_, terminal::Error<'w, tls::Tls<R>>>,
        ) -> terminal::Processed<batch::Produced<'id, Self::Batch<'input>>>
        where
            tls::Tls<R>: 'w,
            'd: 'w,
            'w: 'a + 'input,
        {
            let (txn, output, result) = txn.read(|input| input.read_batch(bytes, cap));
            finish(txn, output, result, end)
        }

        fn read_lease<'a, 'w, 'd, ID: route::Identity + 'w>(
            txn: policy::Transaction<'a, 'w, 'd, R, ID>,
            bytes: recv::Lease<'d>,
            end: terminal::Both<'_, terminal::Error<'w, tls::Tls<R>>>,
        ) -> terminal::Processed<Option<Self::Cursor<'w, 'd>>>
        where
            tls::Tls<R>: 'w,
            'd: 'w,
            'w: 'a,
        {
            let (txn, output, result) = txn.read(|input| input.retain(bytes));
            finish(txn, output, result, end)
        }
    }

    impl<R: roles::Protocol> eof::Eof<tls::Tls<R>> for Ingress<R> {
        fn eof<'d, ID: route::Identity + 'd>(
            wire: &mut tls::Connection<'d, R, ID>,
            end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
        ) -> terminal::Processed<()>
        where
            tls::Tls<R>: 'd,
        {
            match wire.peer_eof() {
                Ok(()) => end.output(()),
                Err(cause) => end.terminal(
                    (),
                    terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
                ),
            }
        }
    }

    fn finish<'a, 'w, 'd: 'w, R: roles::Protocol + 'w, ID: route::Identity + 'w, T>(
        mut txn: policy::Transaction<'a, 'w, 'd, R, ID, buffers::Release>,
        output: T,
        result: Result<(), crate::Error>,
        end: terminal::Both<'_, terminal::Error<'w, tls::Tls<R>>>,
    ) -> terminal::Processed<T>
    where
        'w: 'a,
    {
        let flushed = txn.finish();
        let closed = txn.is_peer_done();
        txn.complete();
        match result.and(flushed) {
            Ok(()) if closed => end.eof(output),
            Ok(()) => end.output(output),
            Err(cause) => end.terminal(
                output,
                terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
            ),
        }
    }
};
