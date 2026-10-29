pub mod common;

use std::{sync::Arc, time::Duration};

use common::{
    Signer, native,
    times::{Absent, Fixed},
};
use dope_tls::config::Ext as _;
use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    pki_types::{CertificateDer, UnixTime},
    time_provider::TimeProvider,
};

#[test]
fn supplied_time() {
    let signer = Signer::new([9; 32]);
    let cert = CertificateDer::from(
        signer
            .certificate("host.local", rcgen::CertificateParams::default())
            .expect("signed certificate"),
    );
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("trust anchor");
    let roots = Arc::new(roots);
    let server = Arc::new(
        ServerConfig::try_tls13()
            .expect("server builder")
            .with_no_client_auth()
            .with_single_cert(vec![cert], signer.key())
            .expect("server identity"),
    );
    let fixed: Arc<dyn TimeProvider> = Arc::new(Fixed(UnixTime::since_unix_epoch(
        Duration::from_secs(1_735_689_600),
    )));
    for (provider, present) in [(fixed, true), (Arc::new(Absent), false)] {
        let mut config = ClientConfig::try_tls13()
            .expect("client builder")
            .with_root_certificates(Arc::clone(&roots))
            .with_no_client_auth();
        config.time_provider = provider;
        let mut client = Connection::Client(
            ClientConnection::new(Arc::new(config), "host.local".try_into().expect("name"))
                .expect("client opens before certificate use"),
        );
        let mut server =
            Connection::Server(ServerConnection::new(Arc::clone(&server)).expect("server"));

        let result = native::pump(&mut client, &mut server);
        if present {
            result.expect("supplied time admits certificate");
            assert!(!client.is_handshaking() && !server.is_handshaking());
        } else {
            assert!(matches!(
                result,
                Err(native::Error::Tls(rustls::Error::FailedToGetCurrentTime))
            ));
        }
    }
}
