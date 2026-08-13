use std::io;

use dope::core::io::recv;
use dope::net::wire::{self, batch, reclaim, reservation, send};
use o3::buffer::bytes;

use crate::state::api::capabilities::Status as _;
use crate::tls::{
    endpoints, open,
    receive::{self, policy, waiters},
    roles,
};
use crate::{error, tls, transmissions};

impl<R: roles::Protocol> wire::Wire for tls::Tls<R> {
    type Connection<'d, const ID: u8> = tls::Connection<'d, R, ID>;
    type ConnectionStorage<const ID: u8> = endpoints::SessionStorage<R, ID>;
    type InitConfig<'d, const ID: u8> = endpoints::Bound<'d, R, ID>;
    type RuntimeContext<'d, const ID: u8> = endpoints::Runtime<'d, R, ID>;
    type Open<'a, 'd, const ID: u8>
        = reservation::ReservedOpen<
        'a,
        Self::Connection<'d, ID>,
        Self::StorageBackend<'d>,
        Self::RuntimeContext<'d, ID>,
    >
    where
        'd: 'a;
    type OpenError = error::Error;
    type Recv<'a> = bytes::Bytes<bytes::Pooled<'a>>;
    type RecvBatch<'a> = receive::Batch<'a>;
    type RetainedRecv<'d> = receive::Retained<'d>;
    type StorageBackend<'d> = tls::SendState<'d>;
    type Reclaim = reclaim::OnSubmit;
    type Receive = policy::Policy<R>;

    const RECV_CREDIT: bool = true;

    fn connection_storage<const ID: u8>(
        capacity: usize,
    ) -> io::Result<Self::ConnectionStorage<ID>> {
        let role = R::storage::<ID>(capacity)?;
        Ok(endpoints::SessionStorage::from_role(role))
    }

    fn holds_plain<'d, const ID: u8>(
        _: &Self::Connection<'d, ID>,
        send: &Self::StorageBackend<'d>,
    ) -> bool {
        !send::StorageBackend::as_slice(send).is_empty()
    }

    fn runtime_context<'d, const ID: u8>(
        limits: wire::RuntimeLimits,
        config: Self::InitConfig<'d, ID>,
    ) -> io::Result<Self::RuntimeContext<'d, ID>>
    where
        Self: 'd,
    {
        let layout = config.buffer_layout(limits)?;
        let endpoints::Bound { role, storage, .. } = config;
        let buffers = storage.bind_buffers(layout)?;
        let role = R::runtime::<ID>(limits, role, &storage.role)?;
        Ok(endpoints::Runtime {
            retry: None,
            buffers,
            waiters: waiters::Queue::with_capacity(limits.max_connections()),
            role,
        })
    }

    fn prepare_open<'a, 'd, const ID: u8>(
        runtime: &'a mut Self::RuntimeContext<'d, ID>,
    ) -> Result<Option<Self::Open<'a, 'd, ID>>, error::Error>
    where
        'd: 'a,
    {
        let (tls, send) = match runtime.retry.take() {
            Some(value) => value,
            None => match open::Open::new(runtime).try_take()? {
                Some(value) => value,
                None => return Ok(None),
            },
        };
        Ok(Some(reservation::ReservedOpen::new(runtime, tls, send)))
    }

    fn process_recv<'a, 'd, const ID: u8>(
        wire: &mut Self::Connection<'d, ID>,
        runtime: &mut Self::RuntimeContext<'d, ID>,
        bytes: &'a mut [u8],
        capacity: &batch::Capacity<Self>,
    ) -> Self::RecvBatch<'a>
    where
        'd: 'a,
    {
        let batch = receive::Ingress::<R, ID>::new(&mut wire.state, &mut runtime.role)
            .read_batch(bytes, capacity);
        debug_assert!(batch.len() <= capacity.items().get());
        batch
    }

    fn process_retained_recv<'a, 'd, const ID: u8>(
        wire: &mut Self::Connection<'d, ID>,
        runtime: &mut Self::RuntimeContext<'d, ID>,
        mut bytes: recv::Lease<'a>,
    ) -> Option<Self::RetainedRecv<'a>>
    where
        'd: 'a,
    {
        let retained = receive::Ingress::<R, ID>::new(&mut wire.state, &mut runtime.role)
            .read_retained(bytes.as_mut_slice());
        retained.into_cursor(bytes)
    }

    fn bind_recv_credit<'d, const ID: u8>(
        recv: &mut Self::RetainedRecv<'d>,
        credit: wire::RecvCredit<'d, ID>,
    ) -> Result<wire::RecvCreditReceipt<'d, ID>, wire::RecvCredit<'d, ID>> {
        recv.bind_recv_credit(credit)
    }

    fn recv_eof<'d, const ID: u8>(wire: &mut Self::Connection<'d, ID>) {
        let _ = wire.state.tls.peer_eof();
        wire.state.close = true;
    }

    fn prepare_send<'a, 'd, const ID: u8>(
        wire: &'a mut Self::Connection<'d, ID>,
        send: send::Storage<'a, Self::StorageBackend<'d>>,
        plain: send::Plain<'a>,
    ) -> send::Prepared<'a, Self::Reclaim> {
        let mut sender = transmissions::Sender::new(wire);
        sender.prepare(send, plain)
    }

    fn prepare_send_vectored<'a, 'd, const ID: u8>(
        wire: &'a mut Self::Connection<'d, ID>,
        send: send::Storage<'a, Self::StorageBackend<'d>>,
        vectored: send::Vectored<'a>,
    ) -> send::Prepared<'a, Self::Reclaim> {
        let mut sender = transmissions::Sender::new(wire);
        sender.prepare_vectored(send, vectored)
    }

    fn submit_failed<'d, const ID: u8>(wire: &mut Self::Connection<'d, ID>) {
        wire.send_inflight = false;
    }

    fn after_send<'a, 'd, const ID: u8>(
        wire: &'a mut Self::Connection<'d, ID>,
        send: send::Storage<'a, Self::StorageBackend<'d>>,
        sent: send::Sent,
    ) -> send::Transition<'a, Self::Reclaim> {
        let mut sender = transmissions::Sender::new(wire);
        sender.after_send(send, sent)
    }

    fn flush_pending<'a, 'd, const ID: u8>(
        wire: &'a mut Self::Connection<'d, ID>,
        send: send::Storage<'a, Self::StorageBackend<'d>>,
    ) -> send::Prepared<'a, Self::Reclaim> {
        let mut sender = transmissions::Sender::new(wire);
        sender.flush(send)
    }

    fn graceful_close<'a, 'd, const ID: u8>(
        wire: &'a mut Self::Connection<'d, ID>,
        mut send: send::Storage<'a, Self::StorageBackend<'d>>,
    ) -> send::Prepared<'a, Self::Reclaim> {
        use crate::tls::egress::Egress;

        let Some(buffer) = transmissions::SendProtocol::try_buffer(wire, &mut *send) else {
            return send.empty().close_after();
        };
        let mut egress = Egress::new(wire);
        egress.seal_close_notify(buffer);
        let close_after = egress.propagate_close();
        let mut sender = transmissions::Sender::new(wire);
        sender.finish(send, 0, close_after)
    }
}
