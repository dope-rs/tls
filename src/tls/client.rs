use std::sync::Arc;

use o3::base::marker::ThreadBound;
use rustls::{ClientConfig, pki_types::ServerName};

/// A worker-owned client target. Clones retain its native configuration and session cache.
#[derive(Clone, Debug)]
pub struct Plan {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) name: ServerName<'static>,
    _bound: ThreadBound,
}

impl Plan {
    pub fn new(config: Arc<ClientConfig>, name: ServerName<'static>) -> Self {
        Self {
            config,
            name,
            _bound: ThreadBound::NEW,
        }
    }
}
