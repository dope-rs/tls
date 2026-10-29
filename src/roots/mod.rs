use o3::alloc::{self, VecExt as _};
use rustls::pki_types::{Der, TrustAnchor};

pub(crate) use sealed::Sealed;

mod sealed;

/// Fallible construction of the bundled trust store.
pub trait Ext: Sealed + Sized {
    /// Retains every bundled trust anchor and its borrowed static DER fields.
    fn try_webpki() -> Result<Self, alloc::Error>;
}

impl Ext for rustls::RootCertStore {
    fn try_webpki() -> Result<Self, alloc::Error> {
        let anchors = webpki_roots::TLS_SERVER_ROOTS;
        let mut roots = Vec::try_new(anchors.len())?;
        roots.extend(anchors.iter().map(|anchor| {
            TrustAnchor {
                subject: Der::from_slice(anchor.subject.as_ref()),
                subject_public_key_info: Der::from_slice(anchor.subject_public_key_info.as_ref()),
                name_constraints: anchor
                    .name_constraints
                    .as_ref()
                    .map(|bytes| Der::from_slice(bytes.as_ref())),
            }
        }));
        Ok(Self { roots })
    }
}
