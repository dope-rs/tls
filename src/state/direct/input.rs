use std::io::{self, BufRead as _, Write as _};

use dope::core::driver::route;
use o3::buffer::write::consume;

use crate::{
    error, staging,
    state::{buffers, direct::Plain, staged},
    tls::{Connection, roles},
};

/// One exclusive input projection whose authenticated prefix cannot exceed
/// the ciphertext already consumed from that same projection.
pub(crate) struct Input<'a> {
    bytes: &'a mut [u8],
    used: usize,
    len: usize,
}

impl Input<'_> {
    /// Publishes only authenticated plaintext in its actual input or pool owner.
    /// The cursor remains private until its single input projection is released.
    pub(crate) fn owned<'d, B: AsMut<[u8]>, R: roles::Protocol + 'd, ID: route::Identity + 'd>(
        state: &mut Connection<'d, R, ID>,
        mut bytes: B,
        recv: buffers::Reserve<'d>,
    ) -> (staged::Output<'d>, Plain<B>) {
        let mut input = Input {
            bytes: bytes.as_mut(),
            used: 0,
            len: 0,
        };
        let mut staged = staged::Staged::Ready(recv);
        let mut result = Ok(());
        while input.used != input.bytes.len() && !state.peer_closed && !state.failed {
            // SAFETY: used starts at zero. Rustls read_tls returns this exact
            // slice reader's count unchanged, bounded by the unread suffix;
            // no operation changes this private input projection.
            let mut tail = unsafe { input.bytes.get_unchecked(input.used..) };
            let count = match state.native.read_tls(&mut tail) {
                Ok(count) => count,
                Err(cause) => {
                    result = Err(error::Error::Io(cause));
                    break;
                }
            };
            input.used += count;
            if count == 0 {
                break;
            }
            result = Self::process(state).and(input.copy_plain(state, &mut staged));
            if result.is_err() {
                break;
            }
        }
        state.failed |= result.is_err();
        let (chunk, released) = match staged {
            staged::Staged::Ready(recv) => {
                drop(recv);
                (None, buffers::Release::Released)
            }
            staged::Staged::Retained(chunk) => (Some(chunk), buffers::Release::Retained),
            staged::Staged::Released => (None, buffers::Release::Released),
        };
        let output = staged::Output {
            chunk,
            control: result,
            released,
        };
        let len = input.len;
        (output, Plain { bytes, len })
    }

    fn process<R: roles::Protocol, ID: route::Identity>(
        state: &mut Connection<'_, R, ID>,
    ) -> Result<(), error::Error> {
        let output = state.native.process_new_packets()?;
        state.peer_closed |= output.peer_has_closed();
        if !state.local_closed && !state.native.is_handshaking() {
            // Empty plaintext publishes Rustls's queued KeyUpdate records.
            consume::Error::check(state.native.writer().write(&[])?, 0)
                .map_err(|_| error::Error::InvalidBufferProgress)?;
        }
        Ok(())
    }

    /// Promotes the first complete record when it contains earlier input.
    /// Pool admission precedes compaction, preserving bytes on rejection.
    fn copy_plain<'d, R: roles::Protocol + 'd, ID: route::Identity + 'd>(
        &mut self,
        state: &mut Connection<'d, R, ID>,
        staged: &mut staged::Staged<'d>,
    ) -> Result<(), error::Error> {
        loop {
            let mut reader = state.native.reader();
            let plain = match reader.fill_buf() {
                Ok([]) => return Ok(()),
                Ok(plain) => plain,
                Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(cause) => return Err(error::Error::Io(cause)),
            };
            let len = plain.len();
            if consume::Error::check(len, self.used - self.len).is_err() {
                if self.len == 0 {
                    staged.copy(plain)?;
                    reader.consume(len);
                    continue;
                }
                // SAFETY: only admitted writes increase len; the original
                // exclusive projection retains that authenticated prefix.
                let prior = unsafe { self.bytes.get_unchecked_mut(..self.len) };
                let prefix = prior.len().min(staging::MAX_PLAINTEXT);
                staged.copy(&prior[..prefix])?;
                prior.copy_within(prefix.., 0);
                self.len -= prefix;
                consume::Error::check(len, self.used - self.len)
                    .map_err(|_| error::Error::InvalidBufferProgress)?;
            }
            let end = self.len + len;
            // SAFETY: admission above proves end <= used <= this unchanged
            // input's extent. This exact target has the plaintext's length.
            let target = unsafe { self.bytes.get_unchecked_mut(self.len..end) };
            target.copy_from_slice(plain);
            self.len = end;
            reader.consume(len);
        }
    }
}

const _: () = assert!(size_of::<Input<'static>>() == 4 * size_of::<usize>());
