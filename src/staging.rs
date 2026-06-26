//! Shared sizing for the per-connection TLS staging buffers.

use shin::record::{HEADER_LEN, MAX_CIPHERTEXT_BODY};

/// Max size of one TLS 1.3 record on the wire (header + spec-max ciphertext body).
pub(crate) const MAX_TLS_RECORD: usize = HEADER_LEN + MAX_CIPHERTEXT_BODY;
/// Headroom above one record for in-place AEAD open/compaction.
pub(crate) const STAGING_HEADROOM: usize = 8 * 1024;
/// Capacity of each per-connection staging buffer (egress / recv / send).
pub(crate) const TLS_STAGING_CAP: usize = MAX_TLS_RECORD + STAGING_HEADROOM;
