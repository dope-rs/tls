use crate::tls::roles;
use crate::{staging, tls};
use dope::core::driver::route;
use dope::{
    core::io::transfer::{self, progress::Bytes},
    net::wire::{send, terminal},
};
use o3::{buffer::pool, depot::array};
use send::progress;
use std::io::{self, Write as _};

pub(super) struct Egress<'a, 'd, R: roles::Protocol + 'd, ID: route::Identity + 'd> {
    wire: &'a mut tls::Connection<'d, R, ID>,
}
impl<'a, 'd, R: roles::Protocol + 'd, ID: route::Identity + 'd> Egress<'a, 'd, R, ID> {
    pub(super) fn new(wire: &'a mut tls::Connection<'d, R, ID>) -> Self {
        Self { wire }
    }

    pub(super) fn encrypt(
        &mut self,
        output: &mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>,
        mut plain: progress::Input<'_, Bytes<'_>>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<()> {
        if self.wire.send_inflight || !self.wire.can_write() {
            return end.output(());
        }
        while !plain.is_empty() && output.spare_len() != 0 && !self.wire.has_debt() {
            let part = plain.take(transfer::Len::fixed::<{ staging::MAX_PLAINTEXT }>());
            let n = match self.wire.native.writer().write(part.as_slice()) {
                Ok(n) => n,
                Err(cause) => {
                    drop(part);
                    return self.fail(end, crate::Error::Io(cause));
                }
            };
            if n == part.as_slice().len() {
                part.commit();
            } else {
                let used = transfer::Len::prefix(n, part.amount());
                drop(part);
                if !used.is_zero() {
                    plain.take(used).commit();
                }
            }
            if let Some(cause) = self.wire.drain(output) {
                return self.fail(end, cause);
            }
            if n == 0 {
                break;
            }
        }
        end.output(())
    }

    /// Encrypts an exact prefix using its retained bound of at most N descriptors.
    pub(super) fn encrypt_many<const N: usize>(
        &mut self,
        output: &mut pool::Cursor<pool::Layout, pool::Borrowed<'d>>,
        mut plain: progress::Input<'_, progress::Vectored<'_, N>>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<()> {
        if self.wire.send_inflight || !self.wire.can_write() {
            return end.output(());
        }
        while !plain.is_empty() && output.spare_len() != 0 && !self.wire.has_debt() {
            let mut parts = plain.take(transfer::Len::fixed::<{ staging::MAX_PLAINTEXT }>());
            let limit = parts.amount();
            let mut slices = array::Vec::<io::IoSlice<'_>, N>::new();
            let mut chunks = parts.take();
            while let Some(slot) = slices.vacancy() {
                let Some(chunk) = chunks.next() else {
                    break;
                };
                let bytes = chunk.bytes();
                slot.insert(io::IoSlice::new(bytes));
            }
            let n = match self.wire.native.writer().write_vectored(slices.as_slice()) {
                Ok(n) => n,
                Err(cause) => return self.fail(end, crate::Error::Io(cause)),
            };
            if n == limit.into_raw() {
                parts.commit();
            } else {
                let used = transfer::Len::prefix(n, limit);
                drop(parts);
                if !used.is_zero() {
                    let mut prefix = plain.take(used);
                    for _ in prefix.take() {}
                    prefix.commit();
                }
            }
            if let Some(cause) = self.wire.drain(output) {
                return self.fail(end, cause);
            }
            if n == 0 {
                break;
            }
        }
        end.output(())
    }

    fn fail(
        &mut self,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
        cause: crate::Error,
    ) -> terminal::Processed<()> {
        self.wire.failed = true;
        end.terminal(
            (),
            terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
        )
    }
}
