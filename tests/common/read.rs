use std::ops::ControlFlow;

use dope::net::wire::receive::mode::access;
use o3::buffer::{self, hold, write::consume};

pub struct Read<F>(pub F);

impl<'d, F: FnMut(&[u8]) -> usize> access::Use<'d, Result<(), consume::Error>> for Read<F> {
    fn apply<R>(
        &mut self,
        head: &mut R,
    ) -> ControlFlow<Result<(), consume::Error>, Result<(), consume::Error>>
    where
        R: buffer::Complete + hold::raw::Retain<'d> + consume::Consume + buffer::raw::Consume,
    {
        let amount = (self.0)(head.as_ref());
        ControlFlow::Break(head.try_consume(amount))
    }
}
