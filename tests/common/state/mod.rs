use dope::core::driver::settings;
use dope_tls::{config, rustls};
use rustls::pki_types::ServerName;

pub const QUEUES: settings::QueueLayout = settings::QueueLayout::fixed::<64, 512>();

pub fn name() -> ServerName<'static> {
    match ServerName::try_from("example.com") {
        Ok(name) => name,
        Err(_) => unreachable!("hostname"),
    }
}

pub fn signing_key() -> Result<config::raw::Identity, dope_tls::Error> {
    config::raw::Identity::from_seed(&[0x3c; 32])
}

pub mod certs;
