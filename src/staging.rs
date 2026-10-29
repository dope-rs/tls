pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;
pub(crate) const MAX_TLS_RECORD: usize = 5 + MAX_PLAINTEXT + 256;
const STAGING_HEADROOM: usize = 8 * 1024;
pub(crate) const TLS_STAGING_CAP: usize = MAX_TLS_RECORD + STAGING_HEADROOM;
