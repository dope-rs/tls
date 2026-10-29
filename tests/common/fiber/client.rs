use dope::core::driver::route::KeyTag;
use dope::net::tcp::Tcp;
use dope_fiber::net::client::Machine;
use dope_tls::tls::{self, roles};

pub const KEY_SEED: [u8; 32] = [0x5a; 32];
pub const PING: &[u8] = b"ping";
pub const PONG: &[u8] = b"pong";
pub const ACK: &[u8] = b"ack";

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
pub struct Client<'p, 'scope, 'w, 'd: 'w> {
    #[pin]
    #[manifold]
    pub machine: Machine<'p, 'scope, 'w, 'd, KeyTag<0>, Tcp, tls::Tls<roles::Client>>,
}
