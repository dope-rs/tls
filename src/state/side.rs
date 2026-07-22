use std::rc::Rc;

use shin::{
    Epoch, Event,
    client::{self, Client},
    record::CipherSuite,
    server::{self, ClientAuth, ClientCertVerifier, ClientIdentity, Server},
};

use crate::{clock::WallClock, error::Error};

pub(super) struct RcVerifier(Rc<dyn ClientCertVerifier>);

impl ClientCertVerifier for RcVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        self.0.verify(identity)
    }
}

type StandardServer = server::Server<WallClock, server::NoGuard, server::NoClientAuth>;
type MutualServer = server::Server<WallClock, server::NoGuard, RcVerifier>;

pub(super) enum Side {
    Client(Box<client::Client<WallClock>>),
    Server(Box<StandardServer>),
    MutualServer(Box<MutualServer>),
}

impl Side {
    pub(super) fn client(
        config: client::Config,
        clock: WallClock,
        configure: impl FnOnce(&mut client::Client<WallClock>),
    ) -> Result<(Self, Vec<Event>), Error> {
        config.validate().map_err(Error::Handshake)?;
        let mut client = Box::new(Client::new(config, clock));
        configure(&mut client);
        let events = client.start().map_err(Error::Handshake)?;
        Ok((Self::Client(client), events))
    }

    pub(super) fn server(config: server::Config, clock: WallClock) -> Result<Self, Error> {
        config.validate().map_err(Error::Handshake)?;
        Ok(Self::Server(Box::new(Server::new(config, clock))))
    }

    pub(super) fn server_mutual(
        config: server::Config,
        clock: WallClock,
        auth: ClientAuth,
        verifier: Rc<dyn ClientCertVerifier>,
    ) -> Result<Self, Error> {
        config.validate().map_err(Error::Handshake)?;
        Ok(Self::MutualServer(Box::new(Server::with_client_auth(
            config,
            clock,
            auth,
            RcVerifier(verifier),
        ))))
    }

    pub(super) fn read(&mut self, epoch: Epoch, data: &[u8]) -> Result<Vec<Event>, shin::Error> {
        match self {
            Self::Client(client) => client.read(epoch, data),
            Self::Server(server) => server.read(epoch, data),
            Self::MutualServer(server) => server.read(epoch, data),
        }
    }

    pub(super) fn send_key_update(&mut self, request: bool) -> Result<Vec<Event>, Error> {
        match self {
            Self::Client(client) => client.send_key_update(request),
            Self::Server(server) => server.send_key_update(request),
            Self::MutualServer(server) => server.send_key_update(request),
        }
        .map_err(Error::Handshake)
    }

    pub(super) fn note_application_data(&mut self) {
        match self {
            Self::Client(client) => client.note_application_data(),
            Self::Server(server) => server.note_application_data(),
            Self::MutualServer(server) => server.note_application_data(),
        }
    }

    pub(super) fn selected_alpn(&self) -> Option<&[u8]> {
        match self {
            Self::Client(client) => client.selected_alpn(),
            Self::Server(server) => server.selected_alpn(),
            Self::MutualServer(server) => server.selected_alpn(),
        }
    }

    pub(super) fn cipher_suite(&self) -> CipherSuite {
        let negotiated = match self {
            Self::Client(client) => client.negotiated_cipher_suite(),
            Self::Server(server) => server.negotiated_cipher_suite(),
            Self::MutualServer(server) => server.negotiated_cipher_suite(),
        };
        negotiated.unwrap_or(CipherSuite::Aes128GcmSha256)
    }
}
