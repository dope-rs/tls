use std::{num::NonZero, ops::ControlFlow};

use dope::{core::io::transfer, net::wire::receive::mode::access};
use o3::buffer::{
    self,
    hold::{self, scope::Input},
    resident,
    write::consume::{self, scope},
};

pub struct Retain<'a, 'd>(pub &'a resident::Budget<'d>);

#[derive(Debug)]
pub enum Error {
    Empty,
    Prefix(scope::Error),
    Retain(hold::Error),
    Bytes,
    Owner,
}

impl<'d> access::Use<'d, Option<Result<resident::Shared<'d>, Error>>> for Retain<'_, 'd> {
    fn apply<R>(
        &mut self,
        head: &mut R,
    ) -> ControlFlow<
        Option<Result<resident::Shared<'d>, Error>>,
        Option<Result<resident::Shared<'d>, Error>>,
    >
    where
        R: buffer::Complete + hold::raw::Retain<'d> + consume::Consume + buffer::raw::Consume,
    {
        let saved = Input::consume(head, self.0, |input| {
            let result = (|| {
                let count = NonZero::new(input.as_slice().len()).ok_or(Error::Empty)?;
                let (prefix, end) = input
                    .try_prefix::<{ transfer::MAX_BYTES as u32 }>(count)
                    .map_err(Error::Prefix)?;
                let saved = prefix
                    .bind(hold::Policy::share())
                    .try_into()
                    .map_err(Error::Retain)?;
                if saved.as_slice() != input.as_slice() {
                    return Err(Error::Bytes);
                }
                if saved.as_slice().as_ptr() != input.as_slice().as_ptr() {
                    return Err(Error::Owner);
                }
                Ok((end, saved))
            })();
            match result {
                Ok((end, saved)) => (Some(end), Some(Ok(saved))),
                Err(cause) => (None, Some(Err(cause))),
            }
        });
        ControlFlow::Break(saved)
    }
}
