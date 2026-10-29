use o3::buffer::Complete as _;
use std::{mem, ops};

use direct::source::Cursor;
use dope::{core::io::transfer, net::wire::receive::mode::access};
use o3::{
    base::num::bounded,
    buffer::{
        self, bytes, pool,
        pool::owners,
        storage::{self, range},
        write::consume,
    },
};

use crate::{
    error,
    state::direct::{self, source::Head},
};

/// Retains each plaintext source with its original wire or driver lifetime.
///
pub struct Retained<'w, 'd> {
    staged: Option<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'w>>>>,
    plain: Option<Cursor<'d>>,
    remaining: transfer::Len,
}

impl<'w, 'd> Retained<'w, 'd> {
    pub(in crate::tls::receive) fn try_new(
        staged: Option<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'w>>>>,
        plain: Cursor<'d>,
    ) -> Result<Option<Self>, error::Error> {
        let staged = staged.filter(|chunk| !chunk.is_empty());
        let body = buffer::Source::remaining(&plain);
        let plain = (body != 0).then_some(plain);
        let stage = staged.as_ref().map_or(0, buffer::Source::remaining);
        let len = bounded::Usize::<{ transfer::MAX_BYTES }>::ZERO
            .try_add(stage)
            .map_err(error::Error::Staged)?
            .try_add(body)
            .map_err(error::Error::Retained)?;
        if len.get() == 0 {
            return Ok(None);
        }
        Ok(Some(Self {
            staged,
            plain,
            remaining: transfer::Len::from_count(len),
        }))
    }
}

impl<'w, 'd> buffer::Source for Retained<'w, 'd> {
    type View<'input>
        = Retention<'input, 'w, 'd>
    where
        Self: 'input;

    fn remaining(&self) -> usize {
        self.remaining.into_raw()
    }
}

impl transfer::Length for Retained<'_, '_> {
    fn len(&self) -> transfer::Len {
        self.remaining
    }
}

impl AsRef<[u8]> for Retained<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        if let Some(staged) = self.staged.as_ref().filter(|head| !head.is_empty()) {
            staged.as_ref()
        } else {
            self.plain.as_ref().map_or(&[], AsRef::as_ref)
        }
    }
}

impl<'w, 'd> buffer::Complete for Retained<'w, 'd> {
    fn view(&self) -> Self::View<'_> {
        let backing = if let Some(staged) = self.staged.as_ref().filter(|head| !head.is_empty()) {
            Backing::Staged(staged.view())
        } else if let Some(plain) = &self.plain {
            Backing::Plain(plain.view())
        } else {
            Backing::Empty
        };
        Retention { backing }
    }
}

impl<'w, 'd> buffer::Cursor for Retained<'w, 'd> {
    fn try_get<'input>(
        &'input self,
        range: ops::Range<usize>,
    ) -> Result<Self::View<'input>, range::Error> {
        let backing = match self.view().backing {
            Backing::Staged(view) => Backing::Staged(view.try_get(range)?),
            Backing::Plain(view) => Backing::Plain(view.try_get(range)?),
            Backing::Empty => {
                <[u8] as buffer::Cursor>::try_get(&[], range)?;
                Backing::Empty
            }
        };
        Ok(Retention { backing })
    }
}

impl consume::Consume for Retained<'_, '_> {
    fn remaining(&self) -> usize {
        self.as_ref().len()
    }

    fn try_consume(&mut self, amount: usize) -> Result<(), consume::Error> {
        let Some(mut head) = access::Sequence::next(self) else {
            return consume::Error::check(amount, 0);
        };
        head.try_consume(amount)?;
        access::Head::commit(head);
        Ok(())
    }

    fn consume_max(&mut self, max: usize) -> usize {
        let Some(mut head) = access::Sequence::next(self) else {
            return 0;
        };
        let amount = head.consume_max(max);
        access::Head::commit(head);
        amount
    }
}

impl<'w, 'd> access::Sequence<'d> for Retained<'w, 'd> {
    type Head<'head>
        = Current<'head, 'w, 'd>
    where
        Self: 'head;

    fn next(&mut self) -> Option<Self::Head<'_>> {
        let Self {
            staged,
            plain,
            remaining: left,
        } = self;
        if let Some(staged) = staged.as_mut().filter(|staged| !staged.is_empty()) {
            return Some(Current::staged(staged, left));
        }
        let head = plain.as_mut()?.head()?;
        Some(Current::plain(head, left))
    }
}

const _: () = assert!(
    mem::size_of::<Retained<'_, '_>>()
        <= mem::size_of::<Option<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'_>>>>>(
        ) + mem::size_of::<Option<Cursor<'_>>>()
            + mem::size_of::<usize>()
);

/// Checked TLS plaintext tied to the backing proof without retention or accounting.
#[doc(hidden)]
pub struct Retention<'input, 'w: 'input, 'd: 'input> {
    pub(super) backing: Backing<'input, 'w, 'd>,
}

pub(super) enum Backing<'input, 'w: 'input, 'd: 'input> {
    Empty,
    Staged(
        <storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'w>>> as buffer::Source>::View<
            'input,
        >,
    ),
    Plain(<Cursor<'d> as buffer::Source>::View<'input>),
}

#[doc(hidden)]
pub struct Current<'input, 'w: 'input, 'd: 'input> {
    pub(super) backing: HeadBacking<'input, 'w, 'd>,
    left: &'input mut transfer::Len,
    before: usize,
}

pub(super) enum HeadBacking<'input, 'w: 'input, 'd: 'input> {
    Staged(bytes::Cursor<'input, 'w>),
    Plain(Head<'input, 'd>),
}

impl<'input, 'w: 'input, 'd: 'input> Current<'input, 'w, 'd> {
    fn staged(
        staged: &'input mut storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'w>>>,
        left: &'input mut transfer::Len,
    ) -> Self {
        Self {
            before: staged.len(),
            backing: HeadBacking::Staged(bytes::Cursor::new(staged)),
            left,
        }
    }

    fn plain(head: Head<'input, 'd>, left: &'input mut transfer::Len) -> Self {
        Self {
            before: buffer::Source::remaining(&head),
            backing: HeadBacking::Plain(head),
            left,
        }
    }
}

impl<'input, 'w: 'input, 'd: 'input> buffer::Read<'input> for Retention<'input, 'w, 'd> {
    fn as_slice(&self) -> &'input [u8] {
        match &self.backing {
            Backing::Empty => &[],
            Backing::Staged(plan) => buffer::Read::as_slice(plan),
            Backing::Plain(plan) => buffer::Read::as_slice(plan),
        }
    }

    fn try_split<const N: usize>(self) -> Result<(&'input [u8; N], Self), consume::Error> {
        let (head, backing) = match self.backing {
            Backing::Empty => {
                let (head, _) = buffer::Read::try_split(&[][..])?;
                (head, Backing::Empty)
            }
            Backing::Staged(plan) => {
                let (head, tail) = buffer::Read::try_split(plan)?;
                (head, Backing::Staged(tail))
            }
            Backing::Plain(plan) => {
                let (head, tail) = buffer::Read::try_split(plan)?;
                (head, Backing::Plain(tail))
            }
        };
        Ok((head, Self { backing }))
    }
}

impl<'w, 'd> buffer::Source for Current<'_, 'w, 'd> {
    type View<'input>
        = Retention<'input, 'w, 'd>
    where
        Self: 'input;

    fn remaining(&self) -> usize {
        self.as_ref().len()
    }
}

impl<'w, 'd> buffer::Cursor for Current<'_, 'w, 'd> {
    fn try_get<'input>(
        &'input self,
        range: ops::Range<usize>,
    ) -> Result<Self::View<'input>, range::Error> {
        let backing = match &self.backing {
            HeadBacking::Staged(head) => Backing::Staged(head.try_get(range)?),
            HeadBacking::Plain(head) => Backing::Plain(head.try_get(range)?),
        };
        Ok(Retention { backing })
    }
}

impl<'w, 'd> buffer::Complete for Current<'_, 'w, 'd> {
    fn view(&self) -> Self::View<'_> {
        let backing = match &self.backing {
            HeadBacking::Staged(head) => Backing::Staged(head.view()),
            HeadBacking::Plain(head) => Backing::Plain(head.view()),
        };
        Retention { backing }
    }
}

impl AsRef<[u8]> for Current<'_, '_, '_> {
    fn as_ref(&self) -> &[u8] {
        buffer::Read::as_slice(&self.view())
    }
}

impl consume::Consume for Current<'_, '_, '_> {
    fn remaining(&self) -> usize {
        self.as_ref().len()
    }

    fn try_consume(&mut self, amount: usize) -> Result<(), consume::Error> {
        match &mut self.backing {
            HeadBacking::Staged(head) => head.try_consume(amount),
            HeadBacking::Plain(head) => head.try_consume(amount),
        }
    }

    fn consume_max(&mut self, max: usize) -> usize {
        match &mut self.backing {
            HeadBacking::Staged(head) => head.consume_max(max),
            HeadBacking::Plain(head) => head.consume_max(max),
        }
    }
}

impl<'w, 'd> access::Head<'d> for Current<'_, 'w, 'd> {
    fn commit(self) {
        let consumed = self.before - self.as_ref().len();
        match self.backing {
            HeadBacking::Staged(head) => head.commit(),
            HeadBacking::Plain(head) => access::Head::commit(head),
        }
        *self.left = transfer::Len::prefix(self.left.into_raw() - consumed, *self.left);
    }
}

const _: () = {
    assert!(mem::size_of::<Current<'_, '_, '_>>() <= 6 * mem::size_of::<usize>());
    assert!(mem::size_of::<Retention<'_, '_, '_>>() == 4 * mem::size_of::<usize>());
};
