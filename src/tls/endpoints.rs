use std::{cell, io};

use dope::net::wire;
use o3::buffer;
use shin::client::config;
use shin::crypto::ticket;

use crate::state;
use crate::tls::receive::waiters;
use crate::tls::{self, open, roles};
use crate::{error, staging};

const DEFAULT_STAGED_RECORDS: usize = 64;
const DEFAULT_CIPHERTEXT_SLOTS: usize = 128;

/// Capacity-bound TLS session state whose handshake workspaces are recycled.
pub struct SessionStorage<R: roles::Protocol = roles::Server, const ID: u8 = 0> {
    pub(crate) role: R::Storage<ID>,
    buffers: cell::OnceCell<BufferPools>,
}

impl<R: roles::Protocol, const ID: u8> SessionStorage<R, ID> {
    /// Records session capacity; binding an endpoint allocates its exact
    /// workspace layout once for every slot.
    pub fn try_with_capacity(capacity: usize) -> io::Result<Self> {
        let role = R::storage::<ID>(capacity)?;
        Ok(Self::from_role(role))
    }

    pub(super) fn from_role(role: R::Storage<ID>) -> Self {
        Self {
            role,
            buffers: cell::OnceCell::new(),
        }
    }

    #[doc(hidden)]
    pub fn bind_endpoint(&self, role: R::Endpoint<ID>) -> Bound<'_, R, ID> {
        Bound {
            staged_records: None,
            ciphertext_slots: None,
            role,
            storage: self,
        }
    }

    pub(super) fn bind_buffers(&self, layout: BufferLayout) -> io::Result<&BufferPools> {
        if let Some(buffers) = self.buffers.get() {
            return if buffers.layout == layout {
                Ok(buffers)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS session storage is already bound to another buffer layout",
                ))
            };
        }
        let recv = buffer::Pool::try_new(layout.recv_slots(), layout.recv_capacity())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let send = buffer::Pool::try_new(layout.send_slots(), layout.send_capacity())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.buffers
            .set(BufferPools { layout, recv, send })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS session storage buffer layout changed while binding",
                )
            })?;
        self.buffers.get().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS session storage buffer binding failed",
            )
        })
    }
}

pub struct Bound<'d, R: roles::Protocol = roles::Server, const ID: u8 = 0> {
    pub(super) staged_records: Option<usize>,
    pub(super) ciphertext_slots: Option<usize>,
    pub(super) role: R::Endpoint<ID>,
    pub(super) storage: &'d SessionStorage<R, ID>,
}

pub struct Configuration<R: roles::Protocol = roles::Server> {
    pub(super) role: R::Config,
    pub(super) staged_records: Option<usize>,
    pub(super) ciphertext_slots: Option<usize>,
}

impl<R: roles::Protocol> Configuration<R> {
    pub(super) fn from_role(role: R::Config) -> Self {
        Self {
            role,
            staged_records: None,
            ciphertext_slots: None,
        }
    }

    pub fn bind<'d, const ID: u8>(self, storage: &'d SessionStorage<R, ID>) -> Bound<'d, R, ID> {
        let Self {
            role,
            staged_records,
            ciphertext_slots,
        } = self;
        let role = R::bind::<ID>(role);
        Bound {
            staged_records,
            ciphertext_slots,
            role,
            storage,
        }
    }

    /// Bounds independently retained staged records. One additional cursor is
    /// reserved for the record currently being assembled.
    pub fn with_staged_record_budget(mut self, records: usize) -> Self {
        self.staged_records = Some(records);
        self
    }

    /// Bounds connections that may concurrently retain outbound ciphertext.
    pub fn with_ciphertext_budget(mut self, slots: usize) -> Self {
        self.ciphertext_slots = Some(slots);
        self
    }

    pub fn buffer_layout(&self, limits: wire::RuntimeLimits) -> io::Result<BufferLayout> {
        buffer_layout(self.staged_records, self.ciphertext_slots, limits)
    }
}

impl Configuration<roles::Client> {
    #[doc(hidden)]
    pub fn from_plan(plan: tls::ClientPlan) -> Self {
        Self::from_role(plan)
    }

    pub fn client(config: config::Config) -> Result<Self, error::Error> {
        Ok(Self::from_role(tls::ClientPlan::new(config)?))
    }

    pub fn client_mutual(
        config: config::Config,
        identity: config::Identity,
    ) -> Result<Self, error::Error> {
        Ok(Self::from_role(tls::ClientPlan::mutual(config, identity)?))
    }
}

impl<R: roles::Protocol, const ID: u8> Bound<'_, R, ID> {
    pub(super) fn buffer_layout(&self, limits: wire::RuntimeLimits) -> io::Result<BufferLayout> {
        buffer_layout(self.staged_records, self.ciphertext_slots, limits)
    }
}

fn buffer_layout(
    staged_records: Option<usize>,
    ciphertext_slots: Option<usize>,
    limits: wire::RuntimeLimits,
) -> io::Result<BufferLayout> {
    let max_connections = limits.max_connections();
    let retained_slots = staged_records
        .unwrap_or(DEFAULT_STAGED_RECORDS)
        .min(max_connections);
    let recv_slots = retained_slots.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS staged record slot overflow",
        )
    })?;
    let send_slots = nonzero_budget(
        ciphertext_slots,
        DEFAULT_CIPHERTEXT_SLOTS,
        max_connections,
        "TLS ciphertext budget must be nonzero",
    )?;
    BufferLayout::try_new(recv_slots, send_slots)
}

fn nonzero_budget(
    configured: Option<usize>,
    default: usize,
    max_connections: usize,
    zero_message: &'static str,
) -> io::Result<usize> {
    let slots = configured.unwrap_or(default).min(max_connections);
    if slots == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, zero_message));
    }
    Ok(slots)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferLayout {
    recv_slots: usize,
    send_slots: usize,
    recv_capacity: usize,
    staging_capacity: usize,
    payload_bytes: usize,
}

impl BufferLayout {
    pub(crate) fn try_new(recv_slots: usize, send_slots: usize) -> io::Result<Self> {
        let payload_bytes = recv_slots
            .checked_mul(staging::MAX_TLS_RECORD)
            .and_then(|bytes| {
                send_slots
                    .checked_mul(staging::TLS_STAGING_CAP)
                    .and_then(|send| bytes.checked_add(send))
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "TLS buffer size overflow")
            })?;
        Ok(Self {
            recv_slots,
            send_slots,
            recv_capacity: staging::MAX_TLS_RECORD,
            staging_capacity: staging::TLS_STAGING_CAP,
            payload_bytes,
        })
    }

    pub fn recv_slots(self) -> usize {
        self.recv_slots
    }

    pub fn send_slots(self) -> usize {
        self.send_slots
    }

    pub fn recv_capacity(self) -> usize {
        self.recv_capacity
    }

    pub fn send_capacity(self) -> usize {
        self.staging_capacity
    }

    /// Returns pool payload bytes without allocator or pool metadata.
    pub fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferUsage {
    recv_available: usize,
    send_available: usize,
}

impl BufferUsage {
    pub(crate) fn new(recv_available: usize, send_available: usize) -> Self {
        Self {
            recv_available,
            send_available,
        }
    }

    pub fn recv_available(self) -> usize {
        self.recv_available
    }

    pub fn send_available(self) -> usize {
        self.send_available
    }
}

pub(super) struct BufferPools {
    layout: BufferLayout,
    pub(super) recv: buffer::Pool,
    pub(super) send: buffer::Pool,
}

pub struct Runtime<'d, R: roles::Protocol, const ID: u8> {
    pub(super) retry: Option<(tls::Connection<'d, R, ID>, tls::SendState<'d>)>,
    pub(super) buffers: &'d BufferPools,
    pub(super) waiters: waiters::Queue<'d, ID>,
    pub(super) role: R::Runtime<'d, ID>,
}

impl<R: roles::Protocol, const ID: u8> Runtime<'_, R, ID> {
    #[doc(hidden)]
    pub fn buffer_usage(&self) -> BufferUsage {
        BufferUsage::new(self.buffers.recv.available(), self.buffers.send.available())
    }
}

impl<'d, R: roles::Protocol, const ID: u8> Runtime<'d, R, ID> {
    #[doc(hidden)]
    pub fn open_state(
        &mut self,
    ) -> Result<Option<state::State<'d, R::Session<'d, ID>>>, error::Error> {
        Ok(open::Open::new(self)
            .try_take()?
            .map(|(connection, send)| connection.into_state(send)))
    }
}

impl<P: roles::ServerPolicy, const ID: u8> Runtime<'_, roles::Server<P>, ID> {
    pub fn replace_ticket_keys(&mut self, keys: Option<ticket::Keys>) {
        self.role.shard.replace_ticket_keys(keys);
    }
}

impl<'d, R: roles::Protocol, const ID: u8>
    wire::OpenRollback<tls::Connection<'d, R, ID>, tls::SendState<'d>> for Runtime<'d, R, ID>
{
    fn rollback_open(&mut self, open: (tls::Connection<'d, R, ID>, tls::SendState<'d>)) {
        self.retry = Some(open);
    }
}
