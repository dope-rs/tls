use o3::collections::{LeaseSlab, LeaseSlabError, SlabLease};
use shin::client;
use shin::client::config::Config;
use shin::connection::{DriveError, Epoch, EventSink};
use shin::server;
use shin::server::config::{ClientCertVerifier, ConnectionConfig, EarlyDataGuard};
use shin::wire::handshake::workspace::HandshakeWorkspace;

use crate::{clock::WallClock, error::Error};

mod sealed {
    pub trait Sealed {}
}

#[doc(hidden)]
pub trait Session: sealed::Sealed {
    fn send_key_update_into<S: EventSink + ?Sized>(
        &mut self,
        request: bool,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;

    fn note_application_data(&mut self);

    fn selected_alpn(&self) -> Option<&[u8]>;
}

pub(crate) trait ClientSession: Session {
    fn start_into<S: EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;

    fn read_into<S: EventSink + ?Sized>(
        &mut self,
        epoch: Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
}

pub(crate) trait ServerSession: Session {
    fn read_into<G, V, S>(
        &mut self,
        epoch: Epoch,
        data: &[u8],
        shard: &mut server::Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized;
}

pub struct Client(Box<client::Client<WallClock>>);

#[doc(hidden)]
pub struct PooledClient<'d>(SlabLease<'d, client::Client<WallClock>>);

pub struct Server(Box<server::Server<WallClock>>);

#[doc(hidden)]
pub struct PooledServer<'d>(SlabLease<'d, server::Server<WallClock>>);

macro_rules! impl_session {
    ($session:ty) => {
        impl sealed::Sealed for $session {}

        impl Session for $session {
            fn send_key_update_into<S: EventSink + ?Sized>(
                &mut self,
                request: bool,
                events: &mut S,
            ) -> Result<(), DriveError<S::Error>> {
                self.0.send_key_update_into(request, events)
            }

            fn note_application_data(&mut self) {
                self.0.note_application_data();
            }

            fn selected_alpn(&self) -> Option<&[u8]> {
                self.0.selected_alpn()
            }
        }
    };
}

macro_rules! impl_client_session {
    ($session:ty) => {
        impl ClientSession for $session {
            fn start_into<S: EventSink + ?Sized>(
                &mut self,
                events: &mut S,
            ) -> Result<(), DriveError<S::Error>> {
                self.0.start_into(events)
            }

            fn read_into<S: EventSink + ?Sized>(
                &mut self,
                epoch: Epoch,
                data: &[u8],
                events: &mut S,
            ) -> Result<(), DriveError<S::Error>> {
                self.0.read_into(epoch, data, events)
            }
        }
    };
}

macro_rules! impl_server_session {
    ($session:ty) => {
        impl ServerSession for $session {
            fn read_into<G, V, S>(
                &mut self,
                epoch: Epoch,
                data: &[u8],
                shard: &mut server::Shard<G, V>,
                events: &mut S,
            ) -> Result<(), DriveError<S::Error>>
            where
                G: EarlyDataGuard,
                V: ClientCertVerifier,
                S: EventSink + ?Sized,
            {
                self.0.read_into(epoch, data, shard, events)
            }
        }
    };
}

impl_session!(Client);
impl_session!(PooledClient<'_>);
impl_client_session!(Client);
impl_client_session!(PooledClient<'_>);
impl_session!(Server);
impl_session!(PooledServer<'_>);
impl_server_session!(Server);
impl_server_session!(PooledServer<'_>);

#[doc(hidden)]
pub struct Pool<T>(LeaseSlab<T>);

impl<T> Pool<T> {
    pub(crate) fn with_capacity(capacity: usize) -> Result<Self, LeaseSlabError> {
        Ok(Self(LeaseSlab::try_with_capacity(capacity)?))
    }
}

impl Client {
    pub(super) fn new(
        config: Config,
        clock: WallClock,
        configure: impl FnOnce(&mut client::Client<WallClock>),
    ) -> Result<Self, Error> {
        config.validate().map_err(Error::Handshake)?;
        let mut client = Box::new(client::Client::with_workspace(
            config,
            clock,
            HandshakeWorkspace::for_client(),
        ));
        configure(&mut client);
        Ok(Self(client))
    }
}

impl<'d> PooledClient<'d> {
    pub(super) fn new_in(
        pool: &'d Pool<client::Client<WallClock>>,
        config: Config,
        clock: WallClock,
        configure: impl FnOnce(&mut client::Client<WallClock>),
    ) -> Result<Self, Error> {
        config.validate().map_err(Error::Handshake)?;
        let vacant = pool.0.vacant_entry().ok_or(Error::BufferUnavailable)?;
        let mut client = vacant.insert(client::Client::with_workspace(
            config,
            clock,
            HandshakeWorkspace::for_client(),
        ));
        configure(&mut client);
        Ok(Self(client))
    }
}

impl Server {
    pub(super) fn new(config: ConnectionConfig, clock: WallClock) -> Result<Self, Error> {
        config.validate().map_err(Error::Handshake)?;
        Ok(Self(Box::new(server::Server::with_workspace(
            config,
            clock,
            HandshakeWorkspace::for_server(),
        ))))
    }
}

impl<'d> PooledServer<'d> {
    pub(super) fn new_in(
        pool: &'d Pool<server::Server<WallClock>>,
        config: ConnectionConfig,
        clock: WallClock,
    ) -> Result<Self, Error> {
        config.validate().map_err(Error::Handshake)?;
        let vacant = pool.0.vacant_entry().ok_or(Error::BufferUnavailable)?;
        Ok(Self(vacant.insert(server::Server::with_workspace(
            config,
            clock,
            HandshakeWorkspace::for_server(),
        ))))
    }
}

const _: () = assert!(size_of::<Client>() == size_of::<usize>());
const _: () = assert!(size_of::<Server>() == size_of::<usize>());
const _: () = assert!(size_of::<PooledClient<'static>>() == size_of::<usize>());
const _: () = assert!(size_of::<PooledServer<'static>>() == size_of::<usize>());
