//! Explicit AWS-LC configuration for worker-owned TLS endpoints.

use std::{sync::Arc, time};

use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;
use rustls::version::TLS13;
use rustls::{ClientConfig, ConfigBuilder, ConfigSide, NamedGroup, ServerConfig, WantsVerifier};

use crate::Error;

pub mod raw;

/// Explicit TLS 1.3 cryptography with stable feature-independent ordering.
pub trait ProviderExt: Sized {
    fn tls13() -> Arc<Self>;
}

impl ProviderExt for CryptoProvider {
    fn tls13() -> Arc<Self> {
        let mut provider = aws_lc_rs::default_provider();
        provider
            .cipher_suites
            .retain(|suite| suite.tls13().is_some());
        provider
            .kx_groups
            .sort_by_key(|group| group.name() == NamedGroup::X25519MLKEM768);
        Arc::new(provider)
    }
}

/// Starts native configurations with explicit TLS 1.3 cryptography and checked system time.
pub trait Ext: ConfigSide + Sized {
    fn try_tls13() -> Result<ConfigBuilder<Self, WantsVerifier>, Error>;
}

impl Ext for ClientConfig {
    fn try_tls13() -> Result<ConfigBuilder<Self, WantsVerifier>, Error> {
        Ok(
            Self::builder_with_details(CryptoProvider::tls13(), Arc::new(Time))
                .with_protocol_versions(&[&TLS13])?,
        )
    }
}

impl Ext for ServerConfig {
    fn try_tls13() -> Result<ConfigBuilder<Self, WantsVerifier>, Error> {
        Ok(
            Self::builder_with_details(CryptoProvider::tls13(), Arc::new(Time))
                .with_protocol_versions(&[&TLS13])?,
        )
    }
}

#[derive(Debug)]
struct Time;

impl TimeProvider for Time {
    fn current_time(&self) -> Option<UnixTime> {
        let elapsed = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .ok()?;
        Some(UnixTime::since_unix_epoch(elapsed))
    }
}
