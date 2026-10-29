use dope_tls::tls::Tls;
use dope_tls::tls::roles::Server;
type Wire = Tls<Server>;
mod bound;
pub use bound::Bound;
pub mod credit;
pub mod retain;
use crate::common::state::{name, signing_key};
use dope::core::driver::route::KeyTag;
use dope::net::{tcp::Tcp, wire::open};
use dope_fiber::net::server::Listener;
use dope_test::harness::peer;
use dope_tls::{config, tls::endpoint};
use std::{
    io::{self, BufRead as _, Write},
    sync::Arc,
    time::Duration,
};

pub const FIRST: &[u8] = b"fragmented";
pub const SECOND: &[u8] = b"-provided";
pub const TAIL_RECORDS: usize = 33;
pub const MAX_CONNECTIONS: usize = 4;

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
pub struct App<'n, 'p, 's, 'scope, 'w, 'd: 's + 'w, F: FnMut(open::Error<'w, Wire>)> {
    #[pin]
    #[manifold]
    pub pool: Listener<'n, 'p, 's, 'scope, 'w, 'd, KeyTag<0>, Tcp, Wire, F>,
}

pub struct Peer<'socket> {
    pub socket: &'socket peer::Stream<'socket>,
    pub tls: rustls::ClientConnection,
}

impl<'socket> Peer<'socket> {
    pub fn try_server() -> Result<(endpoint::Config, [u8; 32]), dope_tls::Error> {
        let key = signing_key()?;
        let pubkey = key.public_key();
        let end = endpoint::Config::from(Arc::new(key.server()?));
        Ok((end, pubkey))
    }

    pub fn establish(
        socket: &'socket peer::Stream<'socket>,
        pubkey: [u8; 32],
    ) -> Result<Self, Connect> {
        socket.set_nodelay(true).map_err(Connect::Io)?;
        socket
            .read_wait(Some(Duration::from_secs(3)))
            .map_err(Connect::Io)?;
        let mut peer = Self {
            socket,
            tls: rustls::ClientConnection::new(
                Arc::new(config::raw::Identity::client(pubkey).map_err(Connect::Config)?),
                name(),
            )
            .map_err(Connect::Tls)?,
        };

        for _ in 0..64 {
            peer.try_flush()?;
            if !peer.tls.is_handshaking() {
                break;
            }
            peer.try_read()?;
        }
        if peer.tls.is_handshaking() {
            return Err(Connect::Handshake);
        }
        peer.try_flush()?;
        Ok(peer)
    }

    fn try_flush(&mut self) -> Result<(), Connect> {
        while self.tls.wants_write() {
            let used = self.tls.write_tls(&mut self.socket).map_err(Connect::Io)?;
            if used == 0 {
                return Err(Connect::Io(io::ErrorKind::WriteZero.into()));
            }
        }
        Ok(())
    }

    fn try_read(&mut self) -> Result<(), Connect> {
        let read = self.tls.read_tls(&mut self.socket).map_err(Connect::Io)?;
        if read == 0 {
            return Err(Connect::Closed);
        }
        self.tls.process_new_packets().map_err(Connect::Tls)?;
        Ok(())
    }

    pub fn seal(&mut self, body: &[u8]) -> Result<Vec<u8>, Connect> {
        self.tls.writer().write_all(body).map_err(Connect::Io)?;
        let mut wire = Vec::new();
        while self.tls.wants_write() {
            let used = self.tls.write_tls(&mut wire).map_err(Connect::Io)?;
            if used == 0 {
                return Err(Connect::Io(io::ErrorKind::WriteZero.into()));
            }
        }
        Ok(wire)
    }

    pub fn try_send(&mut self, body: &[u8]) -> Result<(), Connect> {
        let mut rest = body;
        while !rest.is_empty() {
            let used = self.tls.writer().write(rest).map_err(Connect::Io)?;
            self.try_flush()?;
            if used == 0 {
                return Err(Connect::Io(io::ErrorKind::WriteZero.into()));
            }
            rest = &rest[used..];
        }
        Ok(())
    }

    pub fn try_recv(&mut self) -> Result<Vec<u8>, Connect> {
        loop {
            let data = match self.tls.reader().fill_buf() {
                Ok([]) => return Err(Connect::Closed),
                Ok(data) => data.to_vec(),
                Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => {
                    self.try_read()?;
                    self.try_flush()?;
                    continue;
                }
                Err(cause) => return Err(Connect::Io(cause)),
            };
            self.tls.reader().consume(data.len());
            return Ok(data);
        }
    }
}

#[derive(Debug)]
pub enum Connect {
    Io(io::Error),
    Config(dope_tls::Error),
    Tls(rustls::Error),
    Closed,
    Handshake,
}

pub mod client;
