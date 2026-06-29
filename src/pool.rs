//! Per-thread free-list of TLS staging buffers, sized to concurrent TLS I/O
//! rather than live connections (C2). Thread-per-core => no atomics.

use std::cell::RefCell;

use o3::buffer::Rolling;

use crate::staging::TLS_STAGING_CAP;

type Buf = Box<Rolling<TLS_STAGING_CAP>>;

thread_local! {
    static FREE: RefCell<Vec<Buf>> = const { RefCell::new(Vec::new()) };
}

fn acquire() -> Buf {
    FREE.with_borrow_mut(Vec::pop)
        .unwrap_or_else(o3::mem::boxed_zeroed::<Rolling<TLS_STAGING_CAP>>)
}

fn release(mut buf: Buf) {
    // Reset to empty: a recycled buffer must never expose a prior conn's bytes.
    let len = buf.len();
    buf.consume(len);
    FREE.with_borrow_mut(|free| free.push(buf));
}

#[derive(Clone, Copy)]
enum Class {
    Egress,
    Recv,
    Send,
}

impl Class {
    fn on_borrow(self) {
        match self {
            Self::Egress => crate::memstats::egress_borrow(),
            Self::Recv => crate::memstats::recv_borrow(),
            Self::Send => crate::memstats::send_borrow(),
        }
    }

    fn on_release(self) {
        match self {
            Self::Egress => crate::memstats::egress_release(),
            Self::Recv => crate::memstats::recv_release(),
            Self::Send => crate::memstats::send_release(),
        }
    }
}

/// A staging buffer borrowed from the pool on first `push`, returned when it
/// drains empty. Mirrors `Rolling`'s surface; unbacked it reads as empty.
pub(crate) struct Pooled {
    buf: Option<Buf>,
    class: Class,
}

impl Pooled {
    pub(crate) fn egress() -> Self {
        Self::new(Class::Egress)
    }

    pub(crate) fn recv() -> Self {
        Self::new(Class::Recv)
    }

    pub(crate) fn send() -> Self {
        Self::new(Class::Send)
    }

    fn new(class: Class) -> Self {
        Self { buf: None, class }
    }

    fn ensure(&mut self) -> &mut Rolling<TLS_STAGING_CAP> {
        if self.buf.is_none() {
            self.buf = Some(acquire());
            self.class.on_borrow();
        }
        self.buf.as_mut().expect("just acquired")
    }

    pub(crate) fn spare_capacity(&self) -> usize {
        self.buf
            .as_ref()
            .map_or(TLS_STAGING_CAP, |b| b.spare_capacity())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.as_ref().is_none_or(|b| b.is_empty())
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.buf.as_ref().map_or(&[], |b| b.as_slice())
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.buf {
            Some(b) => b.as_mut_slice(),
            None => &mut [],
        }
    }

    pub(crate) fn push(&mut self, src: &[u8]) {
        if src.is_empty() {
            return;
        }
        self.ensure().push(src);
    }

    /// Stages bytes written by `fill` directly into spare capacity — no
    /// intermediate copy — then commits the length it reports.
    ///
    /// ```ignore
    /// pooled.try_fill(|spare| sealer.seal_into_slice(ct, data, spare))?;
    /// ```
    pub(crate) fn try_fill<E>(
        &mut self,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<(), E> {
        let buf = self.ensure();
        let spare = buf.spare_capacity_mut();
        let cap = spare.len();
        let n = fill(spare)?;
        assert!(n <= cap, "try_fill committed {n} bytes into {cap} of spare");
        // SAFETY: n <= cap, the length of the slice handed to `fill`.
        unsafe { buf.advance(n) };
        Ok(())
    }

    pub(crate) fn consume(&mut self, n: usize) {
        if let Some(b) = self.buf.as_mut() {
            b.consume(n);
        }
    }

    pub(crate) fn release_if_empty(&mut self) {
        if self.buf.as_ref().is_some_and(|b| b.is_empty()) {
            release(self.buf.take().expect("checked some"));
            self.class.on_release();
        }
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            release(buf);
            self.class.on_release();
        }
    }
}
