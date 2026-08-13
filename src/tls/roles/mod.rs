use std::{io, marker, mem, num};

use dope::net::wire;
use o3::buffer;
use o3::collections::slab;
use shin::server::{self, config, workspace};

use crate::state::sessions::{self, ClientPeer as _, ServerPeer as _, clients, servers};
use crate::state::{self, buffers, direct, staged};
use crate::tls::{self, endpoints};
use crate::{clock, error};

mod contract;

pub(crate) use contract::Contract;

pub trait ServerPolicy: Contract + 'static {
    type Guard: config::EarlyDataGuard + 'static;
    type Verifier: config::ClientCertVerifier + 'static;
}

pub struct Standard<G = config::NoGuard>(marker::PhantomData<fn() -> G>);

impl<G> Contract for Standard<G> {}

impl<G> ServerPolicy for Standard<G>
where
    G: config::EarlyDataGuard + 'static,
{
    type Guard = G;
    type Verifier = config::NoClientAuth;
}

pub struct Mutual<G, V>(marker::PhantomData<fn() -> (G, V)>);

impl<G, V> Contract for Mutual<G, V> {}

impl<G, V> ServerPolicy for Mutual<G, V>
where
    G: config::EarlyDataGuard + 'static,
    V: config::ClientCertVerifier + 'static,
{
    type Guard = G;
    type Verifier = config::ClientAuthVerifier<V>;
}

type PolicyShard<P, const ID: u8 = 0> =
    server::Shard<<P as ServerPolicy>::Guard, <P as ServerPolicy>::Verifier, ID>;
type PolicyPreparedShard<P> =
    server::PreparedShard<<P as ServerPolicy>::Guard, <P as ServerPolicy>::Verifier>;
pub struct Server<P = Standard>(marker::PhantomData<fn() -> P>);

pub struct Client(marker::PhantomData<fn()>);

pub struct ServerRuntime<'d, P: ServerPolicy, const DOMAIN: u8> {
    pub(super) shard: PolicyShard<P, DOMAIN>,
    sessions: &'d workspace::Pool<clock::Clock, P::Verifier, DOMAIN, P::Guard>,
}

pub struct ClientRuntime<'d, const ID: u8 = 0> {
    sessions: &'d clients::Initialized<ID>,
}

const _: () = assert!(mem::size_of::<ClientRuntime<'static>>() == mem::size_of::<usize>());

/// Closed role contract used by [`crate::tls::Tls`].
///
/// Implementations are provided only by this crate, so connection storage,
/// runtime state, and borrowed sessions always share the reviewed lifecycle.
///
/// ```compile_fail
/// struct Foreign;
/// impl dope_tls::tls::roles::Contract for Foreign {}
/// ```
pub trait Protocol: Contract + Sized + 'static {
    type Config;
    type Endpoint<const ID: u8>;
    type Runtime<'d, const ID: u8>: 'd;
    type Session<'d, const ID: u8>: sessions::Peer + 'd;
    type Storage<const ID: u8>: 'static;

    #[doc(hidden)]
    fn storage<const ID: u8>(capacity: usize) -> io::Result<Self::Storage<ID>>;

    #[doc(hidden)]
    fn bind<const ID: u8>(config: Self::Config) -> Self::Endpoint<ID>;

    #[doc(hidden)]
    fn runtime<'d, const ID: u8>(
        limits: wire::RuntimeLimits,
        endpoint: Self::Endpoint<ID>,
        storage: &'d Self::Storage<ID>,
    ) -> io::Result<Self::Runtime<'d, ID>>;

    #[doc(hidden)]
    fn open<'d, const ID: u8>(
        _runtime: &mut Self::Runtime<'d, ID>,
        recv: &'d buffer::Pool,
        send: &'d buffer::Pool,
    ) -> Result<Option<state::State<'d, Self::Session<'d, ID>>>, error::Error>;

    #[doc(hidden)]
    fn read_staged<'d, const ID: u8>(
        state: &mut state::State<'d, Self::Session<'d, ID>>,
        _runtime: &mut Self::Runtime<'d, ID>,
        bytes: &[u8],
    ) -> staged::WireRead<'d>;

    #[doc(hidden)]
    fn read_direct<'a, 'd, const ID: u8>(
        state: &mut state::State<'d, Self::Session<'d, ID>>,
        _runtime: &mut Self::Runtime<'d, ID>,
        bytes: &'a mut [u8],
        limit: Option<num::NonZeroUsize>,
    ) -> direct::WireRead<'a>;
}

impl<P: ServerPolicy> Contract for Server<P> {}

impl<P: ServerPolicy> Protocol for Server<P> {
    type Config = PolicyPreparedShard<P>;
    type Endpoint<const ID: u8> = PolicyShard<P, ID>;
    type Runtime<'d, const ID: u8> = ServerRuntime<'d, P, ID>;
    type Session<'d, const ID: u8> = servers::Pooled<'d, ID, P::Guard, P::Verifier>;
    type Storage<const ID: u8> = servers::Storage<ID, P::Guard, P::Verifier>;

    fn storage<const ID: u8>(capacity: usize) -> io::Result<Self::Storage<ID>> {
        let capacity = slab::Capacity::try_from(capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(servers::Storage::new(capacity))
    }

    fn bind<const ID: u8>(shard: Self::Config) -> Self::Endpoint<ID> {
        shard.bind_domain::<ID>()
    }

    fn runtime<'d, const ID: u8>(
        _: wire::RuntimeLimits,
        shard: Self::Endpoint<ID>,
        sessions: &'d Self::Storage<ID>,
    ) -> io::Result<Self::Runtime<'d, ID>> {
        let sessions = sessions.bind(&shard)?;
        Ok(ServerRuntime { shard, sessions })
    }

    fn open<'d, const ID: u8>(
        runtime: &mut Self::Runtime<'d, ID>,
        recv: &'d buffer::Pool,
        send: &'d buffer::Pool,
    ) -> Result<Option<state::State<'d, Self::Session<'d, ID>>>, error::Error> {
        match state::State::from_server_pool(clock::Clock::System, recv, send, runtime.sessions) {
            Ok(state) => Ok(Some(state)),
            Err(error::Error::BufferUnavailable) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn read_staged<'d, const ID: u8>(
        state: &mut state::State<'d, Self::Session<'d, ID>>,
        _runtime: &mut Self::Runtime<'d, ID>,
        bytes: &[u8],
    ) -> staged::WireRead<'d> {
        staged::Reader::new(state).read_one_wire(bytes, &mut |session, epoch, data, events| {
            session.read_into(epoch, data, events)
        })
    }

    fn read_direct<'a, 'd, const ID: u8>(
        state: &mut state::State<'d, Self::Session<'d, ID>>,
        _runtime: &mut Self::Runtime<'d, ID>,
        bytes: &'a mut [u8],
        limit: Option<num::NonZeroUsize>,
    ) -> direct::WireRead<'a> {
        match limit {
            Some(limit) => direct::Reader::new(state).read_batch_in_place(
                bytes,
                limit,
                &mut |session, epoch, data, events| session.read_into(epoch, data, events),
            ),
            None => direct::Reader::new(state)
                .read_in_place(bytes, &mut |session, epoch, data, events| {
                    session.read_into(epoch, data, events)
                }),
        }
    }
}

impl Contract for Client {}

impl Protocol for Client {
    type Config = tls::ClientPlan;
    type Endpoint<const ID: u8> = tls::ClientPlan;
    type Runtime<'d, const ID: u8> = ClientRuntime<'d, ID>;
    type Session<'d, const ID: u8> = clients::Pooled<'d, ID>;
    type Storage<const ID: u8> = clients::Storage<ID>;

    fn storage<const ID: u8>(capacity: usize) -> io::Result<Self::Storage<ID>> {
        let capacity = slab::Capacity::try_from(capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(clients::Storage::new(capacity))
    }

    fn bind<const ID: u8>(plan: Self::Config) -> Self::Endpoint<ID> {
        plan
    }

    fn runtime<'d, const ID: u8>(
        _: wire::RuntimeLimits,
        plan: Self::Endpoint<ID>,
        sessions: &'d Self::Storage<ID>,
    ) -> io::Result<Self::Runtime<'d, ID>> {
        let sessions = sessions.bind(plan)?;
        Ok(ClientRuntime { sessions })
    }

    fn open<'d, const ID: u8>(
        runtime: &mut Self::Runtime<'d, ID>,
        recv: &'d buffer::Pool,
        send: &'d buffer::Pool,
    ) -> Result<Option<state::State<'d, Self::Session<'d, ID>>>, error::Error> {
        let Some(pending) = send.try_acquire_borrowed_buffer() else {
            return Ok(None);
        };
        let Some(session) = clients::Pooled::connect(runtime.sessions) else {
            return Ok(None);
        };
        match state::State::from_client(
            session,
            buffers::Buffers::pooled_with_pending(recv, send, pending),
        ) {
            Ok(state) => Ok(Some(state)),
            Err(error::Error::BufferUnavailable) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn read_staged<'d, const ID: u8>(
        state: &mut state::State<'d, Self::Session<'d, ID>>,
        _runtime: &mut Self::Runtime<'d, ID>,
        bytes: &[u8],
    ) -> staged::WireRead<'d> {
        staged::Reader::new(state).read_one_wire(bytes, &mut |session, epoch, data, events| {
            session.read_into(epoch, data, events)
        })
    }

    fn read_direct<'a, 'd, const ID: u8>(
        state: &mut state::State<'d, Self::Session<'d, ID>>,
        _runtime: &mut Self::Runtime<'d, ID>,
        bytes: &'a mut [u8],
        limit: Option<num::NonZeroUsize>,
    ) -> direct::WireRead<'a> {
        match limit {
            Some(limit) => direct::Reader::new(state).read_batch_in_place(
                bytes,
                limit,
                &mut |session, epoch, data, events| session.read_into(epoch, data, events),
            ),
            None => direct::Reader::new(state)
                .read_in_place(bytes, &mut |session, epoch, data, events| {
                    session.read_into(epoch, data, events)
                }),
        }
    }
}

impl endpoints::Configuration<Server> {
    pub fn server(config: config::Config) -> Result<Self, error::Error> {
        Ok(endpoints::Configuration::from_role(
            server::PreparedShard::new(config).map_err(error::Error::Handshake)?,
        ))
    }
}

impl<G> endpoints::Configuration<Server<Standard<G>>>
where
    G: config::EarlyDataGuard + 'static,
{
    pub fn server_with_early_data_guard(
        config: config::Config,
        guard: G,
    ) -> Result<Self, error::Error> {
        Ok(endpoints::Configuration::from_role(
            server::PreparedShard::with_early_data_guard(config, guard)
                .map_err(error::Error::Handshake)?,
        ))
    }
}

impl<V> endpoints::Configuration<Server<Mutual<config::NoGuard, V>>>
where
    V: config::ClientCertVerifier + 'static,
{
    pub fn server_mutual(
        config: config::Config,
        auth: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, error::Error> {
        Ok(endpoints::Configuration::from_role(
            server::PreparedShard::with_client_auth(config, auth, verifier)
                .map_err(error::Error::Handshake)?,
        ))
    }
}

impl<G, V> endpoints::Configuration<Server<Mutual<G, V>>>
where
    G: config::EarlyDataGuard + 'static,
    V: config::ClientCertVerifier + 'static,
{
    pub fn server_mutual_with_early_data_guard(
        config: config::Config,
        guard: G,
        auth: config::ClientAuth,
        verifier: V,
    ) -> Result<Self, error::Error> {
        Ok(endpoints::Configuration::from_role(
            server::PreparedShard::with_early_data_guard_and_client_auth(
                config, guard, auth, verifier,
            )
            .map_err(error::Error::Handshake)?,
        ))
    }
}
