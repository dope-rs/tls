use dope_tls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rcgen::{ExtendedKeyUsagePurpose, IsCa};

#[derive(Debug)]
pub struct Signer([u8; 32]);

impl Signer {
    pub const fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    pub fn key<'a>(&self) -> PrivateKeyDer<'a> {
        let mut pkcs8 = [0; 48];
        pkcs8[16..].copy_from_slice(&self.0);
        pkcs8[..16].copy_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        PrivatePkcs8KeyDer::from(pkcs8.to_vec()).into()
    }

    pub fn try_sign<'a>(
        &self,
        params: CertificateParams,
    ) -> Result<(Vec<u8>, PrivateKeyDer<'a>), rcgen::Error> {
        let private = self.key();
        let key = KeyPair::from_der_and_sign_algo(&private, &PKCS_ED25519)?;
        let cert = params.self_signed(&key)?.der().to_vec();
        Ok((cert, private))
    }
    pub fn certificate(
        &self,
        name: &str,
        mut params: CertificateParams,
    ) -> Result<Vec<u8>, rcgen::Error> {
        params.subject_alt_names = vec![rcgen::SanType::DnsName(name.try_into()?)];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        Ok(self.try_sign(params)?.0)
    }
}
