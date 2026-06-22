use shin::client::OwnedTrustAnchor;

pub struct WebpkiRoots;

impl WebpkiRoots {
    pub fn anchors() -> Vec<OwnedTrustAnchor> {
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| OwnedTrustAnchor {
                subject_der: ta.subject.as_ref().to_vec(),
                spki_der: Der::wrap_sequence(ta.subject_public_key_info.as_ref()),
            })
            .collect()
    }
}

struct Der;

impl Der {
    fn wrap_sequence(inner: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(inner.len() + 4);
        out.push(0x30);
        Self::write_len(&mut out, inner.len());
        out.extend_from_slice(inner);
        out
    }

    fn write_len(out: &mut Vec<u8>, len: usize) {
        if len < 128 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else if len < 0x1_0000 {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        } else {
            out.push(0x83);
            out.push((len >> 16) as u8);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
    }
}
