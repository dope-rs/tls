use std::sync::Arc;

use o3::alloc::{BoxSliceExt as _, array::Block};

use crate::tls::client;
pub(super) use contract::Contract;

mod contract;

pub struct Server;

pub struct Client;

/// Closed endpoint role; each opened connection owns its protocol state.
pub trait Protocol: Sized {
    type Config;

    #[doc(hidden)]
    const SEND_ON_OPEN: bool;

    #[doc(hidden)]
    fn open(config: &Self::Config, seal: Contract) -> Result<rustls::Connection, crate::Error>;
}

impl Protocol for Server {
    type Config = Arc<rustls::ServerConfig>;
    const SEND_ON_OPEN: bool = false;

    fn open(config: &Self::Config, _seal: Contract) -> Result<rustls::Connection, crate::Error> {
        let mut conn = rustls::ServerConnection::new(Arc::clone(config))?;
        conn.reject_early_data();
        Ok(rustls::Connection::Server(conn))
    }
}

impl Protocol for Client {
    type Config = client::Plan;
    const SEND_ON_OPEN: bool = true;

    fn open(config: &Self::Config, _seal: Contract) -> Result<rustls::Connection, crate::Error> {
        match rustls::ClientConnection::new_with_alpn(
            Arc::clone(&config.config),
            config.name.clone(),
            Block::try_clone(config.config.alpn_protocols.as_slice(), |protocol| {
                Ok(Box::<[u8]>::try_copy(protocol)?.into_vec())
            })?
            .into_vec(),
        ) {
            Ok(conn) => Ok(rustls::Connection::Client(conn)),
            Err(error) => Err(crate::Error::Tls(error)),
        }
    }
}
