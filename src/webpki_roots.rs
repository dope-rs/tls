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
        } else if len < 0x100_0000 {
            out.push(0x83);
            out.push((len >> 16) as u8);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        } else {
            out.push(0x84);
            out.push((len >> 24) as u8);
            out.push((len >> 16) as u8);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
    }
}

#[cfg(test)]
mod der_len_tests {
    use super::Der;

    #[test]
    fn long_form_lengths_round_trip() {
        let mut out = Vec::new();
        Der::write_len(&mut out, 127);
        assert_eq!(out, [0x7f]);

        out.clear();
        Der::write_len(&mut out, 200);
        assert_eq!(out, [0x81, 0xc8]);

        out.clear();
        Der::write_len(&mut out, 0xABCD);
        assert_eq!(out, [0x82, 0xab, 0xcd]);

        out.clear();
        Der::write_len(&mut out, 0xABCDEF);
        assert_eq!(out, [0x83, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn four_byte_form_for_16_mib_and_above() {
        let mut out = Vec::new();
        Der::write_len(&mut out, 0x100_0000);
        assert_eq!(out, [0x84, 0x01, 0x00, 0x00, 0x00]);

        out.clear();
        let len = 0x0123_4567usize;
        Der::write_len(&mut out, len);
        assert_eq!(out, [0x84, 0x01, 0x23, 0x45, 0x67]);
        let decoded = ((out[1] as usize) << 24)
            | ((out[2] as usize) << 16)
            | ((out[3] as usize) << 8)
            | out[4] as usize;
        assert_eq!(decoded, len);
    }
}
