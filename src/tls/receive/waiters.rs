use dope::net::wire::{self, receive};
use o3::collections::queue::slot;

#[derive(Clone, Copy)]
pub(crate) enum Resource {
    Recv,
    HandshakeEgress,
}

pub struct Registration<'a, 'd, const ID: u8> {
    waiters: &'a mut Queue<'d, ID>,
    target: wire::RecvCreditId<'d, ID>,
    pending: bool,
}

pub(crate) struct Queue<'d, const ID: u8> {
    recv: slot::Fifo<wire::RecvCreditGuard<'d, ID>>,
    handshake_egress: slot::Fifo<wire::RecvCreditGuard<'d, ID>>,
}

impl<'d, const ID: u8> Queue<'d, ID> {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            recv: slot::Fifo::with_capacity(capacity),
            handshake_egress: slot::Fifo::with_capacity(capacity),
        }
    }

    pub(crate) fn register(
        &mut self,
        resource: Resource,
        credit: wire::RecvCredit<'d, ID>,
    ) -> Option<Registration<'_, 'd, ID>> {
        let target = credit.id();
        {
            let queue = self.queue(resource);
            let vacant = queue.vacant_entry(target.index())?;
            let guard = credit.claim().ok()?;
            vacant.push_back(guard);
        }
        Some(Registration {
            waiters: self,
            target,
            pending: true,
        })
    }

    pub(crate) fn wake(&mut self, resource: Resource) {
        let Some(guard) = self.queue(resource).pop_front() else {
            return;
        };
        guard.retry();
    }

    pub(crate) fn cancel(&mut self, target: wire::RecvCreditId<'d, ID>) {
        let index = target.index();
        Self::cancel_queue(&mut self.recv, index, target);
        Self::cancel_queue(&mut self.handshake_egress, index, target);
    }

    fn cancel_queue(
        queue: &mut slot::Fifo<wire::RecvCreditGuard<'d, ID>>,
        index: usize,
        target: wire::RecvCreditId<'d, ID>,
    ) {
        let Some(guard) = queue.remove_if(index, |guard| guard.id() == target) else {
            return;
        };
        guard.cancel();
    }

    fn queue(&mut self, resource: Resource) -> &mut slot::Fifo<wire::RecvCreditGuard<'d, ID>> {
        match resource {
            Resource::Recv => &mut self.recv,
            Resource::HandshakeEgress => &mut self.handshake_egress,
        }
    }
}

impl<const ID: u8> receive::Registration for Registration<'_, '_, ID> {
    fn commit(mut self) {
        self.pending = false;
    }
}

impl<const ID: u8> Drop for Registration<'_, '_, ID> {
    fn drop(&mut self) {
        if self.pending {
            self.waiters.cancel(self.target);
        }
    }
}
