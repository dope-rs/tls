mod input;
pub(crate) mod source;

pub(crate) use input::Input;

/// Authenticated plaintext copied into an exclusively owned input prefix.
pub(crate) struct Plain<B> {
    bytes: B,
    len: usize,
}

impl<'a> Plain<&'a mut [u8]> {
    pub(crate) fn into_chunk(self) -> Option<&'a [u8]> {
        if self.len == 0 {
            return None;
        }
        // SAFETY: Input::owned publishes only this exact slice's admitted
        // authenticated prefix. Its private cursor cannot be replaced or
        // reproject the owner before publication.
        Some(unsafe { self.bytes.get_unchecked(..self.len) })
    }
}
