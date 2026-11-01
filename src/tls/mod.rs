use dope::core::driver::route;
use std::{
    io::{self, BufRead as _},
    marker, mem,
};

use dope::{
    core::io::transfer,
    net::wire::{self, failure, send},
};
use o3::{
    base::marker::ThreadBound,
    buffer::{pool, write::consume},
    depot::arena::pool::{Unique, recycle},
    mem::{Lease, Return, lease},
};

use crate::{
    error,
    state::{self, buffers},
};

pub mod client;
pub mod endpoint;
#[doc(hidden)]
pub mod protocol;
#[doc(hidden)]
pub mod receive;
pub mod roles;
mod senders;

impl<R: roles::Protocol> failure::Errors<failure::Open> for Tls<R> {
    type Error<'d>
        = error::Error
    where
        Self: 'd;
}
impl<R: roles::Protocol> failure::Errors<failure::Terminal> for Tls<R> {
    type Error<'d>
        = error::Error
    where
        Self: 'd;
}
impl<R: roles::Protocol> wire::Spec for Tls<R> {
    type Connection<'d, ID: route::Identity + 'd>
        = Connection<'d, R, ID>
    where
        Self: 'd;
    type Storage<ID: route::Identity> = endpoint::Sessions<R, ID>;
    type Binding<'d, ID: route::Identity + 'd>
        = endpoint::Bound<'d, R, ID>
    where
        Self: 'd;
    type Runtime<'w, 'd, ID: route::Identity + 'w>
        = endpoint::Runtime<'w, 'd, R, ID>
    where
        Self: 'w,
        'd: 'w;
    type SendStorage<'d>
        = SendState<'d>
    where
        Self: 'd;
    type OpenFailure = failure::Possible;
    type TerminalFailure = failure::Possible;
    type Bootstrap = protocol::Bootstrap<R>;
    type Receive = protocol::Ingress<R>;
    type Send = protocol::Egress<R>;
}

pub struct Tls<R: roles::Protocol = roles::Server>(marker::PhantomData<R>);

/// One native TLS connection with its actual worker and storage loans.
#[doc(hidden)]
pub struct Connection<
    'd,
    R: roles::Protocol + 'd = roles::Server,
    ID: route::Identity + 'd = route::KeyTag<0>,
> {
    pub(crate) native: rustls::Connection,
    pub(crate) buffers: buffers::Buffers<'d>,
    pub(crate) peer_closed: bool,
    pub(crate) local_closed: bool,
    pub(crate) failed: bool,
    send_inflight: bool,
    _lease: Unique<'d, (), recycle::Header<()>>,
    _thread: ThreadBound,
    role: marker::PhantomData<fn() -> (R, ID)>,
}

impl<'d, R: roles::Protocol + 'd, ID: route::Identity + 'd> Connection<'d, R, ID> {
    pub(crate) fn new(
        native: rustls::Connection,
        buffers: buffers::Buffers<'d>,
        lease: Unique<'d, (), recycle::Header<()>>,
        mut send: SendState<'d>,
    ) -> Result<(Self, SendState<'d>), error::Error> {
        let mut conn = Self {
            native,
            buffers,
            peer_closed: false,
            local_closed: false,
            failed: false,
            send_inflight: false,
            _lease: lease,
            _thread: ThreadBound::NEW,
            role: marker::PhantomData,
        };
        if let Some(out) = send.buffer.as_mut() {
            conn.emit_into(out)?;
        } else if conn.native.wants_write() {
            return Err(error::Error::BufferUnavailable);
        }
        send.drop_empty();
        Ok((conn, send))
    }

    pub(crate) fn can_write(&self) -> bool {
        !self.failed && !self.local_closed && !self.native.is_handshaking()
    }
    pub(crate) fn peer_eof(&mut self) -> Result<(), error::Error> {
        self.native.read_tls(&mut io::empty())?;
        match self.native.reader().fill_buf() {
            Ok([]) => Ok(()),
            Ok(_) => Err(error::Error::InvalidBufferProgress),
            Err(cause) => {
                self.failed = true;
                Err(error::Error::Io(cause))
            }
        }
    }

    pub(crate) fn seal_close(
        &mut self,
        out: &mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>,
    ) -> Result<(), error::Error> {
        if !self.local_closed && !self.failed {
            self.local_closed = true;
            self.native.send_close_notify();
        }
        self.emit_into(out)
    }

    pub(crate) fn try_buffer<'a>(
        &self,
        store: &'a mut SendState<'d>,
    ) -> Option<&'a mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>> {
        store.try_buffer(self.buffers.send_pool())
    }
    pub(crate) fn has_debt(&self) -> bool {
        !self.send_inflight && self.native.wants_write()
    }
    pub(crate) fn emit_into(
        &mut self,
        out: &mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>,
    ) -> Result<(), error::Error> {
        state::drain(&mut self.native, out)
    }
    pub(crate) fn drain(
        &mut self,
        out: &mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>,
    ) -> Option<error::Error> {
        if self.send_inflight {
            return None;
        }
        match self.emit_into(out) {
            Ok(()) => None,
            Err(cause) => {
                self.failed = true;
                Some(cause)
            }
        }
    }
}

pub struct SendState<'d> {
    buffer: Option<pool::Cursor<pool::Layout, pool::Borrowed<'d>>>,
}

/// One admitted ciphertext cursor, returned to its exact send owner on drop.
pub(super) struct Buffered<'a, 'd> {
    loan: Lease<Vacant<'a, 'd>, lease::Open>,
}

#[repr(transparent)]
struct Vacant<'a, 'd>(&'a mut SendState<'d>);

impl<'d> Return for Vacant<'_, 'd> {
    type Item = pool::Cursor<pool::Layout, pool::Borrowed<'d>>;

    fn return_item(self, cursor: Self::Item) {
        let _ = self.restore(cursor);
    }
}

impl<'d> Vacant<'_, 'd> {
    fn restore(self, cursor: pool::Cursor<pool::Layout, pool::Borrowed<'d>>) -> send::Availability {
        if cursor.is_empty() {
            send::Availability::Released
        } else {
            self.0.buffer = Some(cursor);
            send::Availability::Unchanged
        }
    }
}

impl<'d> Buffered<'_, 'd> {
    pub(super) fn buffer_mut(&mut self) -> &mut pool::Cursor<pool::Layout, pool::Borrowed<'d>> {
        self.loan.item_mut()
    }

    pub(super) fn complete(self) -> send::Availability {
        let (store, cursor) = self.loan.into_parts();
        store.restore(cursor)
    }
}

impl send::Consume for SendState<'_> {
    fn consume_max(&mut self, max: transfer::Len) {
        if let Some(cursor) = self.buffer.as_mut() {
            consume::Consume::consume_max(cursor, max.into_raw());
        }
    }
}
impl<'d> SendState<'d> {
    fn reserve(&mut self, pool: &'d pool::Pool) -> Option<Buffered<'_, 'd>> {
        let cursor = self.buffer.take().or_else(|| pool.view())?;
        Some(Buffered {
            loan: Lease::open(Vacant(self), cursor),
        })
    }

    fn try_buffer(
        &mut self,
        pool: &'d pool::Pool,
    ) -> Option<&mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>> {
        if self.buffer.is_none() {
            self.buffer = pool.view();
        }
        self.buffer.as_mut()
    }
    pub(crate) fn buffer_mut(
        &mut self,
    ) -> Option<&mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>> {
        self.buffer.as_mut()
    }
    pub(crate) fn drop_empty(&mut self) {
        let _ = self.free_empty();
    }
    pub(crate) fn free_empty(&mut self) -> send::Availability {
        if self.buffer.as_ref().is_some_and(pool::Cursor::is_empty) {
            self.buffer = None;
            send::Availability::Released
        } else {
            send::Availability::Unchanged
        }
    }
}
impl send::Store for SendState<'_> {
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_ref().map_or(&[], AsRef::as_ref)
    }
    fn release(self) -> send::Availability {
        if self.buffer.is_some() {
            send::Availability::Released
        } else {
            send::Availability::Unchanged
        }
    }
}
const _: () = assert!(mem::size_of::<Connection<'_>>() <= 4_096);
