use o3::buffer::{pool, pool::owners, storage};
use std::mem;

use crate::{error, state::buffers};

/// Authenticated plaintext retaining its actual pool loan and exact processing result.
pub(crate) struct Output<'d> {
    pub(crate) chunk: Option<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'d>>>>,
    pub(crate) control: Result<(), crate::Error>,
    pub(crate) released: buffers::Release,
}

/// The admitted receive loan is either still exclusive or has been published
/// once as the authenticated prefix retained by this read operation.
pub(super) enum Staged<'d> {
    Ready(buffers::Reserve<'d>),
    Retained(storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'d>>>),
    Released,
}

impl<'d> Staged<'d> {
    pub(super) fn copy(&mut self, plain: &[u8]) -> Result<(), error::Error> {
        let recv = match mem::replace(self, Self::Released) {
            Self::Ready(recv) => recv,
            state => {
                *self = state;
                return Err(error::Error::InvalidBufferProgress);
            }
        };
        *self = Self::Retained(recv.copy(plain)?);
        Ok(())
    }
}
