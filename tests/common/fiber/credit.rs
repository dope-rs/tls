use std::io::{self, Write as _};

use dope_test::harness::peer;

use crate::common::fiber::{Connect, FIRST, Peer};

pub const AFTER_RELEASE: &[u8] = b"after-release";
pub const INDEPENDENT: &[u8] = b"independent";

type Replies = (Vec<u8>, Result<Vec<u8>, Connect>);

pub fn exchange<E>(
    [held, other]: &mut [&peer::Stream<'_>; 2],
    pubkey: [u8; 32],
    body: &[u8],
    joined: bool,
    escaped: bool,
    mut signal: impl FnMut() -> Result<(), E>,
) -> Result<Replies, Error<E>> {
    let mut held = Peer::establish(held, pubkey).map_err(Error::Connect)?;
    let mut other = Peer::establish(other, pubkey).map_err(Error::Connect)?;
    if joined {
        let mut wire = held.seal(FIRST).map_err(Error::Connect)?;
        held.tls.refresh_traffic_keys().map_err(Error::Keys)?;
        wire.extend_from_slice(&held.seal(body).map_err(Error::Connect)?);
        held.socket.write_all(&wire).map_err(Error::Io)?;
    } else {
        held.try_send(body).map_err(Error::Connect)?;
    }
    signal().map_err(Error::Signal)?;
    held.try_send(AFTER_RELEASE).map_err(Error::Connect)?;
    other.try_send(INDEPENDENT).map_err(Error::Connect)?;
    if escaped {
        signal().map_err(Error::Signal)?;
    }
    let reply = held.try_recv().map_err(Error::Connect)?;
    Ok((reply, other.try_recv()))
}

#[derive(Debug)]
pub enum Error<E> {
    Connect(Connect),
    Keys(rustls::Error),
    Io(io::Error),
    Signal(E),
}
