use crate::state::{buffers, staged};
use o3::buffer::pool::owners;
use std::num;

use crate::state::direct::source::Head;
use crate::tls::receive::stream::{Backing, Current, HeadBacking, Retained};
use dope::core::driver::route::Identity;
use dope::core::io::recv;
use dope::net::wire;
use dope::net::wire::receive::{self, batch};
use o3::buffer::{self, bytes, hold, pool, resident, storage};

// SAFETY: Retained's shared projection and next select the same current head.
// Its exclusive head loan preserves that range until the prefix is committed.
unsafe impl buffer::raw::Consume for stream::Retained<'_, '_> {
    fn consume<const MAX: u32>(prefix: buffer::raw::Consumed<'_, '_, Self, MAX>) {
        use receive::mode::access;

        let (cursor, end) = prefix.into_parts();
        if let Some(mut head) = access::Sequence::next(cursor) {
            // SAFETY: next borrows the same initialized head that admitted end.
            <stream::Current<'_, '_, '_> as buffer::raw::Consume>::consume(unsafe {
                buffer::raw::Consumed::from_parts(&mut head, end)
            });
            access::Head::commit(head);
        }
    }
}

use crate::{
    error,
    tls::{
        self,
        receive::{Batch, Ingress, stream},
        roles,
    },
};

pub(super) struct Producer<'s, 'd, 'input, 'f, R: roles::Protocol + 'd, ID: Identity + 'd> {
    pub(super) ingress: Ingress<'s, 'd, R, ID>,
    pub(super) bytes: &'input mut [u8],
    pub(super) control: &'f mut (Result<(), error::Error>, buffers::Release),
}

// SAFETY: read returns at most one pooled chunk and one initialized input prefix.
// Both retain their actual storage owner, and the capacity admits two items.
unsafe impl<'d: 'input, 'input, R: roles::Protocol + 'd, ID: Identity + 'd>
    receive::raw::Producer<'input, tls::Tls<R>> for Producer<'_, 'd, 'input, '_, R, ID>
{
    fn produce(self, _cap: &batch::Capacity<'_, tls::Tls<R>>) -> Batch<'input> {
        let (
            staged::Output {
                chunk,
                control: failure,
                released,
            },
            plain,
        ) = self.ingress.read(self.bytes);
        *self.control = (failure, released);
        Batch {
            owned: chunk,
            plain: plain.into_chunk(),
        }
    }
}

const _: () = {
    use wire::receive::raw;

    // SAFETY: next takes each of the two optional owners once; len counts those
    // same owners, and every yielded slice retains its authenticated lifetime.
    unsafe impl<'a> raw::Batch<'a> for Batch<'a> {
        type Item =
            bytes::Source<'a, storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'a>>>>;

        const MAX_ITEMS: num::NonZero<usize> = num::NonZero::<usize>::MIN.saturating_add(1);

        fn len(&self) -> usize {
            usize::from(self.owned.is_some()) + usize::from(self.plain.is_some())
        }

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(owned) = self.owned.take() {
                return Some(bytes::Source::Owned(owned));
            }
            let plain = self.plain.take()?;
            Some(bytes::Source::Borrowed(plain))
        }
    }
};

// SAFETY: The current immutable view delegates retention to its unchanged backing variant.
unsafe impl<'w, 'd> hold::raw::Retain<'d> for Retained<'w, 'd> {
    fn try_copy<'a>(
        plan: &Self::View<'a>,
        budget: &resident::Budget<'d>,
    ) -> Result<resident::Shared<'d>, hold::Error>
    where
        Self: 'a,
    {
        <Current<'a, 'w, 'd> as hold::raw::Retain<'d>>::try_copy(plan, budget)
    }

    fn charge<'a>(plan: &Self::View<'a>) -> hold::Charge
    where
        Self: 'a,
    {
        <Current<'a, 'w, 'd> as hold::raw::Retain<'d>>::charge(plan)
    }

    fn try_retain<'a>(
        plan: &Self::View<'a>,
        budget: &resident::Budget<'d>,
    ) -> Result<resident::Shared<'d>, hold::Error>
    where
        Self: 'a,
    {
        <Current<'a, 'w, 'd> as hold::raw::Retain<'d>>::try_retain(plan, budget)
    }
}

// SAFETY: each variant exclusively borrows one stable plaintext head.
unsafe impl buffer::raw::Consume for Current<'_, '_, '_> {
    fn consume<const MAX: u32>(prefix: buffer::raw::Consumed<'_, '_, Self, MAX>) {
        let (current, end) = prefix.into_parts();
        match &mut current.backing {
            HeadBacking::Staged(head) => {
                // SAFETY: the matched head exposes exactly Current's byte range.
                bytes::Cursor::consume(unsafe { buffer::raw::Consumed::from_parts(head, end) });
            }
            HeadBacking::Plain(head) => {
                // SAFETY: the matched head exposes exactly Current's byte range.
                Head::consume(unsafe { buffer::raw::Consumed::from_parts(head, end) });
            }
        }
    }
}

// SAFETY: Each immutable backing view retains its exact range or copies those exact bytes.
unsafe impl<'w, 'd> hold::raw::Retain<'d> for Current<'_, 'w, 'd> {
    fn try_copy<'a>(
        plan: &Self::View<'a>,
        budget: &resident::Budget<'d>,
    ) -> Result<resident::Shared<'d>, hold::Error>
    where
        Self: 'a,
    {
        match &plan.backing {
            Backing::Empty => Ok(resident::Shared::new()),
            Backing::Staged(plan) => {
                resident::Exact::try_copy(budget, buffer::Read::as_slice(plan))
                    .map(resident::Exact::into_shared)
                    .map_err(hold::Error::Resident)
            }
            Backing::Plain(plan) => {
                <recv::Shared<'d> as hold::raw::Retain<'d>>::try_copy(plan, budget)
            }
        }
    }

    fn charge<'a>(plan: &Self::View<'a>) -> hold::Charge
    where
        Self: 'a,
    {
        match &plan.backing {
            Backing::Empty => hold::Charge::from_commit(0, 0, 0),
            Backing::Staged(plan) => <storage::Shared<
                owners::Edge<owners::Plain, pool::Borrowed<'w>>,
            > as hold::raw::Retain<'w>>::charge(plan),
            Backing::Plain(plan) => <recv::Shared<'d> as hold::raw::Retain<'d>>::charge(plan),
        }
    }

    fn try_retain<'a>(
        plan: &Self::View<'a>,
        budget: &resident::Budget<'d>,
    ) -> Result<resident::Shared<'d>, hold::Error>
    where
        Self: 'a,
    {
        match &plan.backing {
            Backing::Empty => Ok(resident::Shared::new()),
            Backing::Staged(plan) => plan
                .reborrow()
                .try_own()
                .map(resident::Shared::from)
                .map_err(resident::AllocError::Retain)
                .map_err(hold::Error::Resident),
            Backing::Plain(plan) => {
                <recv::Shared<'d> as hold::raw::Retain<'d>>::try_retain(plan, budget)
            }
        }
    }
}
