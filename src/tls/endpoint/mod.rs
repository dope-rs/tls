use dope::core::driver::{receive::credit, route};
use std::{cell, convert, marker, num, sync::Arc};

use dope::net::{self, wire};
use o3::{
    base::marker::ThreadBound,
    buffer::pool,
    depot::{arena::pool::recycle, capacity},
};
use wire::{domain, open};

use crate::error;
use crate::state::buffers;
use crate::tls::receive::waiters;
use crate::tls::{self, client, roles};
use rustls::pki_types::ServerName;

pub mod layout;

/// Worker-owned connection admission and reusable transport buffers.
pub struct Sessions<R: roles::Protocol = roles::Server, ID: route::Identity = route::KeyTag<0>> {
    capacity: capacity::Count,
    buffers: cell::OnceCell<Pools>,
    role: marker::PhantomData<fn() -> (R, ID)>,
    _bound: ThreadBound,
}

impl<R: roles::Protocol, ID: route::Identity> Sessions<R, ID> {
    /// Records exact connection capacity; binding allocates transport storage.
    pub fn try_new(cap: usize) -> Result<Self, capacity::Error> {
        Ok(Self::from_count(capacity::Count::try_from(cap)?))
    }

    pub(super) fn from_count(capacity: capacity::Count) -> Self {
        Self {
            capacity,
            buffers: cell::OnceCell::new(),
            role: marker::PhantomData,
            _bound: ThreadBound::NEW,
        }
    }

    pub(super) fn bind_pools<T>(
        &self,
        layout: layout::Layout,
        complete: impl FnOnce() -> Result<T, net::Resource>,
    ) -> Result<(&Pools, T), net::Resource> {
        if self.buffers.get().is_some() {
            return Err(net::Resource::Binding(net::BindingError::AlreadyBound));
        }
        let init = Pools {
            sessions: recycle::Store::try_new(self.capacity).map_err(net::Resource::Allocation)?,
            recv: match layout.growing {
                Some(warm) => buffers::Receive::Growing(
                    pool::Growing::try_warm(layout.recv, warm).map_err(net::Resource::Pool)?,
                ),
                None => buffers::Receive::Fixed(
                    pool::Pool::try_from(layout.recv).map_err(net::Resource::Exhausted)?,
                ),
            },
            send: pool::Pool::try_from(layout.send).map_err(net::Resource::Exhausted)?,
        };
        // Reverse binding order drops rejected pools before the completed state.
        let (ready, init) = (complete()?, init);
        if self.buffers.get().is_some() {
            return Err(net::Resource::Binding(net::BindingError::AlreadyBound));
        }
        Ok((self.buffers.get_or_init(|| init), ready))
    }
}

pub struct Bound<'d, R: roles::Protocol = roles::Server, ID: route::Identity = route::KeyTag<0>> {
    pub(super) plan: layout::Plan,
    pub(super) role: R::Config,
    pub(super) storage: &'d Sessions<R, ID>,
}

pub struct Config<R: roles::Protocol = roles::Server> {
    pub(super) role: R::Config,
    plan: layout::Plan,
    _bound: ThreadBound,
}

impl<R: roles::Protocol> Config<R> {
    pub(super) fn from_role(role: R::Config) -> Self {
        Self {
            role,
            plan: layout::Plan::new(),
            _bound: ThreadBound::NEW,
        }
    }

    #[doc(hidden)]
    pub fn bind<'d, ID: route::Identity>(self, store: &'d Sessions<R, ID>) -> Bound<'d, R, ID> {
        let Self { role, plan, .. } = self;
        Bound {
            plan,
            role,
            storage: store,
        }
    }

    /// Sets receive-pool capacity to `max` staged records plus one assembly slot.
    /// Receive waits while all slots are retained. By default all slots are
    /// allocated when the endpoint is bound.
    pub fn with_staged(mut self, max: layout::Staged) -> Self {
        self.plan = self.plan.with_staged(max);
        self
    }

    /// Bounds transport buffers that may concurrently retain outbound ciphertext.
    pub fn with_send(mut self, max: num::NonZero<usize>) -> Self {
        self.plan = self.plan.with_send(max);
        self
    }

    /// Allocates `warm` receive slots at binding, rejecting values above the limit.
    /// Later growth preserves the limit and returns exact allocation errors.
    /// Without this option, binding preallocates the entire receive pool.
    pub fn with_growth(mut self, warm: num::NonZero<u32>) -> Self {
        self.plan = self.plan.with_growth(warm);
        self
    }

    pub const fn plan(&self) -> layout::Plan {
        self.plan
    }
}

impl<R: roles::Protocol, ID: route::Identity> domain::Plan<tls::Tls<R>, ID> for Config<R> {
    type Error = convert::Infallible;

    fn bind<'d>(self, store: &'d Sessions<R, ID>) -> Result<Bound<'d, R, ID>, Self::Error>
    where
        tls::Tls<R>: 'd,
        ID: 'd,
    {
        Ok(Config::bind(self, store))
    }
}

impl From<client::Plan> for Config<roles::Client> {
    fn from(plan: client::Plan) -> Self {
        Self::from_role(plan)
    }
}

impl Config<roles::Client> {
    pub fn client(config: Arc<rustls::ClientConfig>, name: ServerName<'static>) -> Self {
        Self::from_role(client::Plan::new(config, name))
    }
}

impl From<Arc<rustls::ServerConfig>> for Config<roles::Server> {
    /// Uses the native server policy with 0-RTT rejected by this transport.
    fn from(config: Arc<rustls::ServerConfig>) -> Self {
        Self::from_role(config)
    }
}

pub(super) struct Pools {
    pub(super) sessions: recycle::Store<()>,
    pub(super) recv: buffers::Receive,
    pub(super) send: pool::Pool,
}

pub struct Runtime<'w, 'd, R: roles::Protocol + 'w, ID: route::Identity + 'w>
where
    'd: 'w,
{
    pub(super) pending: Option<(tls::Connection<'w, R, ID>, tls::SendState<'w>)>,
    pub(super) buffers: &'w Pools,
    pub(super) waiters: waiters::Queue<'d, ID>,
    pub(super) role: R::Config,
}

impl<R: roles::Protocol, ID: route::Identity> Runtime<'_, '_, R, ID> {
    fn ready(&self) -> Option<waiters::Resource> {
        if self.buffers.recv.available() == 0 {
            return None;
        }
        if self.waiters.has_waiters(waiters::Resource::Recv) {
            return Some(waiters::Resource::Recv);
        }
        if self.buffers.send.available() != 0
            && self.waiters.has_waiters(waiters::Resource::HandshakeEgress)
        {
            return Some(waiters::Resource::HandshakeEgress);
        }
        None
    }
}

impl<'w, 'd, R: roles::Protocol + 'w, ID: route::Identity + 'w>
    open::Runtime<'w, 'd, tls::Tls<R>, ID> for Runtime<'w, 'd, R, ID>
where
    'd: 'w,
{
    fn is_ready(&self) -> bool {
        self.ready().is_some()
    }

    fn take_ready(&mut self) -> Option<credit::Held<'d, ID>> {
        self.waiters.take(self.ready()?)
    }

    fn open<C, T>(
        &mut self,
        context: C,
        consume: impl FnOnce(
            C,
            tls::Connection<'w, R, ID>,
            tls::SendState<'w>,
        )
            -> open::Disposition<T, tls::Connection<'w, R, ID>, tls::SendState<'w>>,
    ) -> open::Outcome<C, T, open::Error<'w, tls::Tls<R>>> {
        let parts = match self.pending.take() {
            Some(parts) => parts,
            None => {
                let Some(lease) = self.buffers.sessions.take() else {
                    return open::Outcome::Unavailable(context);
                };
                let pending = if R::SEND_ON_OPEN {
                    let Some(cursor) = self.buffers.send.view() else {
                        return open::Outcome::Unavailable(context);
                    };
                    Some(cursor)
                } else {
                    None
                };
                let opened = R::open(&self.role, roles::Contract(())).and_then(|conn| {
                    tls::Connection::new(
                        conn,
                        buffers::Buffers::new(&self.buffers.recv, &self.buffers.send),
                        lease,
                        tls::SendState { buffer: pending },
                    )
                });
                match opened {
                    Ok(parts) => parts,
                    Err(error::Error::BufferUnavailable) => {
                        return open::Outcome::Unavailable(context);
                    }
                    Err(cause) => {
                        return open::Outcome::Failed {
                            context,
                            cause: open::Error::from_cause(cause),
                        };
                    }
                }
            }
        };
        let (wire, send) = parts;
        let output = consume(context, wire, send).into_output(|wire, send| {
            self.pending = Some((wire, send));
        });
        open::Outcome::Opened(output)
    }
}
