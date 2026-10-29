use dope::core::io::socket::{BindError, Listener};
use std::net;

pub struct Bound {
    socket: Listener,
    addr: net::SocketAddr,
}

impl Bound {
    pub fn try_new() -> Result<Self, BindError> {
        let bound = Listener::bind(net::SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let addr = bound.local_addr();
        Ok(Self {
            socket: bound,
            addr,
        })
    }

    pub fn into_parts(self) -> (Listener, net::SocketAddr) {
        (self.socket, self.addr)
    }
}
