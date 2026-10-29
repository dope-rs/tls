use o3::{
    alloc,
    depot::queue::tagged::{self, entry},
};
use std::mem;

use dope::{
    core::driver::{
        receive::credit,
        route::{self, table::conn},
    },
    net::wire::receive,
};
use o3::depot::queue::indexed::lanes;
use receive::reserve;

const RECV: usize = 0;
const HANDSHAKE_EGRESS: usize = 1;
const LANES: usize = 2;

enum Proof<'a, 'd, ID: route::Identity> {
    Recv(
        tagged::Linked<
            lanes::Position<'a, credit::Held<'d, ID>, LANES, RECV, conn::Capacity, true>,
            lanes::Rollback,
        >,
    ),
    HandshakeEgress(
        tagged::Linked<
            lanes::Position<
                'a,
                credit::Held<'d, ID>,
                LANES,
                HANDSHAKE_EGRESS,
                conn::Capacity,
                true,
            >,
            lanes::Rollback,
        >,
    ),
}

#[derive(Clone, Copy, Debug)]
pub(in crate::tls) enum Resource {
    Recv,
    HandshakeEgress,
}

pub struct Registration<'a, 'd, ID: route::Identity> {
    proof: Option<Proof<'a, 'd, ID>>,
}

pub(crate) struct Queue<'d, ID: route::Identity> {
    waiters: lanes::Fifo<credit::Held<'d, ID>, LANES, conn::Capacity>,
}

impl<'d, ID: route::Identity> Queue<'d, ID> {
    pub(crate) fn try_new(cap: conn::Capacity) -> Result<Self, alloc::Error> {
        Ok(Self {
            waiters: lanes::Fifo::try_from(cap)?,
        })
    }

    pub(in crate::tls) fn register(
        &mut self,
        kind: Resource,
        credit: credit::Pending<'d, ID>,
    ) -> Result<Registration<'_, 'd, ID>, entry::Error<conn::Capacity>> {
        let target = credit.id();
        let proof = match kind {
            Resource::Recv => {
                let vacant = self
                    .waiters
                    .vacant::<RECV>(target.slot().index().into_usize())?;
                let guard = credit.claim();
                Proof::Recv(vacant.insert::<false>(guard))
            }
            Resource::HandshakeEgress => {
                let vacant = self
                    .waiters
                    .vacant::<HANDSHAKE_EGRESS>(target.slot().index().into_usize())?;
                let guard = credit.claim();
                Proof::HandshakeEgress(vacant.insert::<false>(guard))
            }
        };
        Ok(Registration { proof: Some(proof) })
    }

    pub(in crate::tls) fn take(&mut self, kind: Resource) -> Option<credit::Held<'d, ID>> {
        match kind {
            Resource::Recv => self.waiters.pop_front::<RECV>(),
            Resource::HandshakeEgress => self.waiters.pop_front::<HANDSHAKE_EGRESS>(),
        }
    }

    pub(in crate::tls) fn wake(&mut self, kind: Resource) {
        if let Some(guard) = self.take(kind) {
            guard.retry();
        }
    }

    pub(in crate::tls) fn has_waiters(&self, kind: Resource) -> bool {
        match kind {
            Resource::Recv => !tagged::Endpoint::constant::<RECV>(&self.waiters).is_empty(),
            Resource::HandshakeEgress => {
                !tagged::Endpoint::constant::<HANDSHAKE_EGRESS>(&self.waiters).is_empty()
            }
        }
    }

    pub(crate) fn cancel(&mut self, target: credit::Id<'d, ID>) {
        let index = target.slot().index().into_usize();
        let Some(guard) = self.waiters.remove_if(index, |guard| guard.id() == target) else {
            return;
        };
        guard.cancel();
    }
}

impl<ID: route::Identity> reserve::Registration for Registration<'_, '_, ID> {
    fn commit(mut self) {
        if let Some(proof) = self.proof.take() {
            proof.commit();
        }
    }
}

impl<ID: route::Identity> Drop for Registration<'_, '_, ID> {
    fn drop(&mut self) {
        if let Some(proof) = self.proof.take() {
            proof.remove().cancel();
        }
    }
}

impl<'a, 'd, ID: route::Identity> Proof<'a, 'd, ID> {
    fn commit(self) {
        match self {
            Self::Recv(proof) => proof.commit(),
            Self::HandshakeEgress(proof) => proof.commit(),
        }
    }

    fn remove(self) -> credit::Held<'d, ID> {
        match self {
            Self::Recv(proof) => proof.remove(),
            Self::HandshakeEgress(proof) => proof.remove(),
        }
    }
}

const _: () = {
    assert!(
        mem::size_of::<Queue<'_, route::KeyTag<0>>>()
            == 2 * mem::size_of::<usize>() + LANES * 2 * mem::size_of::<u32>()
    );
    assert!(mem::size_of::<Proof<'_, '_, route::KeyTag<0>>>() == 3 * mem::size_of::<usize>());
    assert!(
        mem::size_of::<Registration<'_, '_, route::KeyTag<0>>>()
            == mem::size_of::<Proof<'_, '_, route::KeyTag<0>>>()
    );
};
