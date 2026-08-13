use std::iter;

use shin::client::config;

#[derive(Clone, Debug, Default)]
pub struct Roots {
    index: usize,
}

impl Roots {
    pub const fn new() -> Self {
        Self { index: 0 }
    }

    /// Builds a validated issuer-indexed store that can be shared by endpoints.
    pub fn into_store(self) -> Result<config::TrustStore, config::Error> {
        config::TrustStore::new(self)
    }
}

impl Iterator for Roots {
    type Item = config::OwnedTrustAnchor;

    fn next(&mut self) -> Option<Self::Item> {
        let anchor = webpki_roots::TLS_SERVER_ROOTS.get(self.index)?;
        self.index += 1;
        Some(config::OwnedTrustAnchor::from_der_fields(
            anchor.subject.as_ref(),
            anchor.subject_public_key_info.as_ref(),
            anchor.name_constraints.as_ref().map(|value| value.as_ref()),
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = webpki_roots::TLS_SERVER_ROOTS.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Roots {}
impl iter::FusedIterator for Roots {}
