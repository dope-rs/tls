use std::iter::FusedIterator;

use shin::client::config::OwnedTrustAnchor;

#[derive(Clone, Debug, Default)]
pub struct WebPkiRoots {
    index: usize,
}

impl WebPkiRoots {
    pub const fn new() -> Self {
        Self { index: 0 }
    }
}

impl Iterator for WebPkiRoots {
    type Item = OwnedTrustAnchor;

    fn next(&mut self) -> Option<Self::Item> {
        let anchor = webpki_roots::TLS_SERVER_ROOTS.get(self.index)?;
        self.index += 1;
        Some(OwnedTrustAnchor {
            subject_der: anchor.subject.as_ref().to_vec(),
            spki_der: wrap_sequence(anchor.subject_public_key_info.as_ref()),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = webpki_roots::TLS_SERVER_ROOTS.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for WebPkiRoots {}
impl FusedIterator for WebPkiRoots {}

fn wrap_sequence(inner: &[u8]) -> Vec<u8> {
    let bytes = inner.len().to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let length = &bytes[start..];
    let header_len = if inner.len() < 128 {
        2
    } else {
        2 + length.len()
    };
    let mut out = Vec::with_capacity(header_len + inner.len());
    out.push(0x30);
    if inner.len() < 128 {
        out.push(inner.len() as u8);
    } else {
        out.push(0x80 | length.len() as u8);
        out.extend_from_slice(length);
    }
    out.extend_from_slice(inner);
    out
}
