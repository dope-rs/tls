use crate::state::direct;
use dope::{core::io::recv, net::wire::receive::mode};
use mode::access;
use o3::buffer::Complete as _;
use o3::buffer::{
    self,
    bytes::bounded,
    hold, resident,
    storage::{self, provided, range},
    write::consume,
};
use std::ops;

fn view<'a, 'd>(
    cursor: &'a Cursor<'d>,
    left: usize,
) -> bounded::Value<buffer::View<'a, storage::Shared<provided::Owner<'d>>>> {
    let end = cursor.end;
    let start = end - left;
    let source = buffer::Complete::view(&cursor.bytes).into_inner();
    // SAFETY: Input::owned copied only into the consumed prefix of this exact
    // input owner. Head narrows that immutable prefix without changing storage.
    let proof = unsafe { bounded::raw::Input::new(source).select(start..end) };
    bounded::Value::from_raw(proof)
}

/// Retains the authenticated end while the remaining suffix only shrinks.
pub(crate) struct Cursor<'d> {
    bytes: recv::Shared<'d>,
    end: usize,
    len: usize,
}

impl<'d> Cursor<'d> {
    pub(crate) fn new(plain: direct::Plain<recv::Lease<'d>>) -> Self {
        Self {
            bytes: plain.bytes.into_shared(),
            end: plain.len,
            len: plain.len,
        }
    }

    pub(crate) fn head(&mut self) -> Option<Head<'_, 'd>> {
        if self.len == 0 {
            return None;
        }
        let left = self.len;
        Some(Head {
            cursor: self,
            remaining: left,
        })
    }
}

pub(crate) struct Head<'input, 'd: 'input> {
    cursor: &'input mut Cursor<'d>,
    remaining: usize,
}

impl<'d> buffer::Source for Head<'_, 'd> {
    type View<'input>
        = bounded::Value<buffer::View<'input, storage::Shared<provided::Owner<'d>>>>
    where
        Self: 'input;

    fn remaining(&self) -> usize {
        self.remaining
    }
}

// SAFETY: The selected immutable provided view delegates retention to its original owner.
unsafe impl<'d> hold::raw::Retain<'d> for Head<'_, 'd> {
    fn try_copy<'a>(
        plan: &Self::View<'a>,
        budget: &resident::Budget<'d>,
    ) -> Result<resident::Shared<'d>, hold::Error>
    where
        Self: 'a,
    {
        <recv::Shared<'d> as hold::raw::Retain<'d>>::try_copy(plan, budget)
    }

    fn charge<'a>(plan: &Self::View<'a>) -> hold::Charge
    where
        Self: 'a,
    {
        <recv::Shared<'d> as hold::raw::Retain<'d>>::charge(plan)
    }

    fn try_retain<'a>(
        plan: &Self::View<'a>,
        budget: &resident::Budget<'d>,
    ) -> Result<resident::Shared<'d>, hold::Error>
    where
        Self: 'a,
    {
        <recv::Shared<'d> as hold::raw::Retain<'d>>::try_retain(plan, budget)
    }
}

impl<'d> buffer::Cursor for Head<'_, 'd> {
    fn try_get<'input>(
        &'input self,
        range: ops::Range<usize>,
    ) -> Result<Self::View<'input>, range::Error> {
        self.view().try_get(range)
    }
}

impl<'d> buffer::Complete for Head<'_, 'd> {
    fn view(&self) -> Self::View<'_> {
        view(self.cursor, self.remaining)
    }
}

impl AsRef<[u8]> for Head<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        buffer::Read::as_slice(&view(self.cursor, self.remaining))
    }
}

impl consume::Consume for Head<'_, '_> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn try_consume(&mut self, amount: usize) -> Result<(), consume::Error> {
        consume::Error::check(amount, self.remaining)?;
        self.remaining -= amount;
        Ok(())
    }

    fn consume_max(&mut self, max: usize) -> usize {
        let amount = max.min(self.remaining);
        self.remaining -= amount;
        amount
    }
}

impl<'d> access::Head<'d> for Head<'_, 'd> {
    fn commit(self) {
        self.cursor.len = self.remaining;
    }
}

impl<'d> buffer::Source for Cursor<'d> {
    type View<'input>
        = bounded::Value<buffer::View<'input, storage::Shared<provided::Owner<'d>>>>
    where
        Self: 'input;

    fn remaining(&self) -> usize {
        self.len
    }
}

impl<'d> buffer::Cursor for Cursor<'d> {
    fn try_get<'input>(
        &'input self,
        range: ops::Range<usize>,
    ) -> Result<Self::View<'input>, range::Error> {
        self.view().try_get(range)
    }
}

impl<'d> buffer::Complete for Cursor<'d> {
    fn view(&self) -> Self::View<'_> {
        view(self, self.len)
    }
}

impl AsRef<[u8]> for Cursor<'_> {
    fn as_ref(&self) -> &[u8] {
        buffer::Read::as_slice(&view(self, self.len))
    }
}

// SAFETY: the immutable provided owner retains this exact plaintext view.
unsafe impl buffer::raw::Consume for Head<'_, '_> {
    fn consume<const MAX: u32>(prefix: buffer::raw::Consumed<'_, '_, Self, MAX>) {
        let (head, end) = prefix.into_parts();
        head.remaining -= end.count().get() as usize;
    }
}
