pub mod reentry;

use std::{
    io::{self, Read as _, Write as _},
    num::NonZero,
    os::unix::net::UnixStream,
    sync::Arc,
    time::Duration,
};

use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, InvalidDnsNameError},
    version,
};

use crate::common::Signer;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(rustls::Error),
    Certificate(rcgen::Error),
    Name(InvalidDnsNameError),
    Handshake,
    Close(NonZero<usize>),
}

pub fn transfer(from: &mut Connection, to: &mut Connection) -> Result<(), Error> {
    let mut wire = Vec::new();
    while from.wants_write() {
        if from.write_tls(&mut wire).map_err(Error::Io)? == 0 {
            return Err(Error::Io(io::ErrorKind::WriteZero.into()));
        }
    }
    let mut input = wire.as_slice();
    while !input.is_empty() {
        if to.read_tls(&mut input).map_err(Error::Io)? == 0 {
            return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        to.process_new_packets().map_err(Error::Tls)?;
    }
    Ok(())
}

pub fn pump(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
    for _ in 0..32 {
        if !client.wants_write() && !server.wants_write() {
            return Ok(());
        }
        transfer(client, server)?;
        transfer(server, client)?;
    }
    Err(Error::Io(io::Error::other("TLS flight limit")))
}

type Pair = (
    StreamOwned<ClientConnection, UnixStream>,
    StreamOwned<ServerConnection, UnixStream>,
);

pub fn try_half_closed() -> Result<Pair, Error> {
    let signer = Signer::new([42; 32]);
    let cert = CertificateDer::from(
        signer
            .certificate("example.com", rcgen::CertificateParams::default())
            .map_err(Error::Certificate)?,
    );
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).map_err(Error::Tls)?;
    let provider = Arc::new(aws_lc_rs::default_provider());
    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&version::TLS13])
        .map_err(Error::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .map_err(Error::Tls)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], signer.key())
        .map_err(Error::Tls)?;
    server.send_tls13_tickets = 0;
    let mut client = Connection::Client(
        ClientConnection::new(
            Arc::new(client),
            "example.com".try_into().map_err(Error::Name)?,
        )
        .map_err(Error::Tls)?,
    );
    let mut server =
        Connection::Server(ServerConnection::new(Arc::new(server)).map_err(Error::Tls)?);
    pump(&mut client, &mut server)?;
    if client.is_handshaking() || server.is_handshaking() {
        return Err(Error::Handshake);
    }
    let (client, server) = match (client, server) {
        (Connection::Client(client), Connection::Server(server)) => (client, server),
        _ => unreachable!("roles"),
    };
    let (left, right) = UnixStream::pair().map_err(Error::Io)?;
    for socket in [&left, &right] {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(Error::Io)?;
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(Error::Io)?;
    }
    let mut client = StreamOwned::new(client, left);
    let mut server = StreamOwned::new(server, right);
    client.conn.send_close_notify();
    client.flush().map_err(Error::Io)?;
    if let Some(count) = NonZero::new(server.read(&mut [0; 1]).map_err(Error::Io)?) {
        return Err(Error::Close(count));
    }
    Ok((client, server))
}
