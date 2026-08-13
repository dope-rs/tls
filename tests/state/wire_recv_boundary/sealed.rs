use dope::net::wire::send;

pub(super) fn static_plain(bytes: &'static [u8]) -> send::Plain<'static> {
    // SAFETY: process-static bytes remain fixed and immutable through every
    // possible completion of the in-process send transition.
    unsafe { send::raw::Plain::retain(bytes) }
}
