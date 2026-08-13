use shin::wire::record;

pub(crate) const MAX_TLS_RECORD: usize = record::HEADER_LEN + record::MAX_CIPHERTEXT_BODY;
pub(crate) const TLS13_RECORD_OVERHEAD: usize = record::HEADER_LEN + 1 + record::AEAD_TAG_LEN;
const STAGING_HEADROOM: usize = 8 * 1024;
pub(crate) const TLS_STAGING_CAP: usize = MAX_TLS_RECORD + STAGING_HEADROOM;
