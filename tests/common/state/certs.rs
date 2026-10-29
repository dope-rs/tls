use std::{io, sync::Arc};

use dope_test::harness::peer;
use dope_tls::config::{self, Ext as _};
use rustls::pki_types::CertificateDer;
use rustls::{CertificateError, ClientConfig, RootCertStore, ServerConfig, ServerConnection};

use crate::common::Signer;

#[derive(Debug)]
pub enum Error {
    Config(dope_tls::Error),
    Tls(rustls::Error),
    Certificate(rcgen::Error),
    Io(io::Error),
}

#[derive(Clone, Copy)]
pub enum Kind {
    Raw,
    X509,
}

impl Kind {
    pub fn configs(self) -> Result<(ClientConfig, ServerConfig), Error> {
        match self {
            Self::Raw => {
                let expected =
                    config::raw::Identity::from_seed(&[0x71; 32]).map_err(Error::Config)?;
                let client =
                    config::raw::Identity::client(expected.public_key()).map_err(Error::Config)?;
                let server = config::raw::Identity::from_seed(&[0x72; 32])
                    .map_err(Error::Config)?
                    .server()
                    .map_err(Error::Config)?;
                Ok((client, server))
            }
            Self::X509 => {
                let trusted = Signer::new([0x71; 32])
                    .certificate("trusted.example", rcgen::CertificateParams::default())
                    .map_err(Error::Certificate)?;
                let signer = Signer::new([0x72; 32]);
                let cert = signer
                    .certificate("example.com", rcgen::CertificateParams::default())
                    .map_err(Error::Certificate)?;
                let mut roots = RootCertStore::empty();
                roots
                    .add(CertificateDer::from(trusted))
                    .map_err(Error::Tls)?;
                let client = ClientConfig::try_tls13()
                    .map_err(Error::Config)?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let server = ServerConfig::try_tls13()
                    .map_err(Error::Config)?
                    .with_no_client_auth()
                    .with_single_cert(vec![CertificateDer::from(cert)], signer.key())
                    .map_err(Error::Tls)?;
                Ok((client, server))
            }
        }
    }

    pub fn error(self) -> rustls::Error {
        rustls::Error::InvalidCertificate(match self {
            Self::Raw => CertificateError::ApplicationVerificationFailure,
            Self::X509 => CertificateError::UnknownIssuer,
        })
    }
    pub fn serve(self, mut stream: &peer::Stream<'_>) -> Result<rustls::Error, Error> {
        let (_, config) = self.configs()?;
        let mut server = ServerConnection::new(Arc::new(config)).map_err(Error::Tls)?;
        loop {
            while server.wants_write() {
                server.write_tls(&mut stream).map_err(Error::Io)?;
            }
            if server.read_tls(&mut stream).map_err(Error::Io)? == 0 {
                return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            if let Err(cause) = server.process_new_packets() {
                return Ok(cause);
            }
        }
    }
}
