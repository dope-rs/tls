//! Shared sizing + heap allocation for the per-connection TLS staging buffers.

use o3::buffer::Rolling;
use shin::record::{HEADER_LEN, MAX_CIPHERTEXT_BODY};

/// Max size of one TLS 1.3 record on the wire (header + spec-max ciphertext body).
pub(crate) const MAX_TLS_RECORD: usize = HEADER_LEN + MAX_CIPHERTEXT_BODY;
/// Headroom above one record for in-place AEAD open/compaction.
pub(crate) const STAGING_HEADROOM: usize = 8 * 1024;
/// Capacity of each per-connection staging buffer (egress / recv / send).
pub(crate) const TLS_STAGING_CAP: usize = MAX_TLS_RECORD + STAGING_HEADROOM;

/// Allocate a zeroed `Rolling<CAP>` on the heap, skipping the ~24 KiB stack
/// temporary + memcpy of `Box::new(Rolling::default())`.
#[inline]
pub(crate) fn boxed_rolling<const CAP: usize>() -> Box<Rolling<CAP>> {
    const { assert!(CAP <= u32::MAX as usize, "buffer::Rolling CAP must fit u32") }
    // SAFETY: all-zero is a valid `Rolling` (empty buf, head == tail == 0).
    unsafe { Box::new_zeroed().assume_init() }
}
