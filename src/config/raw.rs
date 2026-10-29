//! Pinned Ed25519 raw public keys for worker-owned TLS configurations.

use std::{ptr, sync::Arc};

use o3::alloc::{BoxExt, BoxSliceExt as _};
use o3::base::marker::ThreadBound;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{AlwaysResolvesClientRawPublicKeys, Resumption};
use rustls::compress::CompressionCache;
use rustls::crypto::aws_lc_rs::sign;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, NoClientAuth, NoServerSessionStorage};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error,
    InconsistentKeys, PeerIncompatible, ServerConfig, SignatureScheme,
};

use crate::config::Ext as _;

/// RFC 8410 Ed25519 SubjectPublicKeyInfo prefix.
const SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// RFC 8410 Ed25519 PKCS#8 PrivateKeyInfo prefix.
const PKCS8: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// An admitted signing identity confined to its constructing worker.
#[derive(Debug)]
pub struct Identity {
    key: Arc<CertifiedKey>,
    public_key: [u8; 32],
    _thread: ThreadBound,
}

impl Identity {
    /// Loads an Ed25519 seed through AWS-LC.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, crate::Error> {
        let mut encoded = [0; PKCS8.len() + 32];
        encoded[..PKCS8.len()].copy_from_slice(&PKCS8);
        encoded[PKCS8.len()..].copy_from_slice(seed);
        let result = sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(encoded.as_slice()));
        for byte in &mut encoded {
            // SAFETY: this exclusive borrow names one live, writable byte.
            unsafe { ptr::write_volatile(byte, 0) };
        }
        let key = result?;
        let spki = key
            .public_key()
            .ok_or_else(|| Error::InconsistentKeys(InconsistentKeys::Unknown))?;
        let public = spki
            .as_ref()
            .strip_prefix(&SPKI)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let cert = CertificateDer::from(Box::<[u8]>::try_copy(spki.as_ref())?.into_vec());
        let certs: Box<[CertificateDer<'static>]> = <Box<_> as BoxExt<_>>::try_new([cert])?;
        let key = Arc::new(CertifiedKey::new(certs.into_vec(), key));
        Ok(Self {
            key,
            public_key: public,
            _thread: ThreadBound::NEW,
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Configures server authentication without requesting a client identity.
    pub fn server(self) -> Result<ServerConfig, crate::Error> {
        self.server_with(None)
    }

    /// Requires the client's configured key and proof of private-key possession.
    pub fn server_auth(self, pin: [u8; 32]) -> Result<ServerConfig, crate::Error> {
        self.server_with(Some(pin))
    }

    fn server_with(self, pin: Option<[u8; 32]>) -> Result<ServerConfig, crate::Error> {
        let builder = ServerConfig::try_tls13()?;
        let verifier: Arc<dyn ClientCertVerifier> = match pin {
            Some(key) => Arc::new(Peer::new(
                key,
                builder.crypto_provider().signature_verification_algorithms,
            )),
            None => Arc::new(NoClientAuth),
        };
        let builder = builder.with_client_cert_verifier(verifier);
        let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(self.key));
        let mut config = builder.with_cert_resolver(resolver);
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(NoServerSessionStorage {});
        if let Some(cache) = Arc::get_mut(&mut config.cert_compression_cache) {
            *cache = CompressionCache::Disabled;
        }
        Ok(config)
    }

    /// Requires the server's configured key and proof of private-key possession.
    pub fn client(pin: [u8; 32]) -> Result<ClientConfig, crate::Error> {
        Self::client_with(pin, None)
    }

    /// Authenticates both peers with their configured raw public keys.
    pub fn mutual(self, pin: [u8; 32]) -> Result<ClientConfig, crate::Error> {
        Self::client_with(pin, Some((self.key, self._thread)))
    }

    fn client_with(
        pin: [u8; 32],
        identity: Option<(Arc<CertifiedKey>, ThreadBound)>,
    ) -> Result<ClientConfig, crate::Error> {
        let builder = ClientConfig::try_tls13()?;
        let verifier = Arc::new(Peer::new(
            pin,
            builder.crypto_provider().signature_verification_algorithms,
        ));
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let mut config = match identity {
            Some((key, _thread)) => builder
                .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(key))),
            None => builder.with_no_client_auth(),
        };
        config.resumption = Resumption::disabled();
        if let Some(cache) = Arc::get_mut(&mut config.cert_compression_cache) {
            *cache = CompressionCache::Disabled;
        }
        Ok(config)
    }
}

#[derive(Debug)]
struct Peer {
    spki: [u8; 44],
    algorithms: WebPkiSupportedAlgorithms,
}

impl Peer {
    fn new(public: [u8; 32], algs: WebPkiSupportedAlgorithms) -> Self {
        let mut spki = [0; 44];
        spki[..12].copy_from_slice(&SPKI);
        spki[12..].copy_from_slice(&public);
        Self {
            spki,
            algorithms: algs,
        }
    }

    fn verify(&self, leaf: &CertificateDer<'_>, chain: &[CertificateDer<'_>]) -> Result<(), Error> {
        if !chain.is_empty() || leaf.as_ref() != self.spki {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(())
    }
}

impl ServerCertVerifier for Peer {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verify(leaf, chain)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for Peer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.verify(leaf, chain)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
