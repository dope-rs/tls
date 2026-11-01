use dope::core::driver::route;
use dope::{
    core::io::transfer::{self, progress::Bytes},
    net::wire::{send, terminal},
};
use o3::{buffer::pool, depot::array};
use send::{progress, reclaim};
use std::{
    io::{self, Write as _},
    task::Poll,
};

use crate::{
    staging,
    tls::{self, roles},
};

pub(crate) struct Sender<'a, 'd, R: roles::Protocol + 'd, ID: route::Identity + 'd> {
    wire: &'a mut tls::Connection<'d, R, ID>,
}

impl<'a, 'd, R: roles::Protocol + 'd, ID: route::Identity + 'd> Sender<'a, 'd, R, ID> {
    pub(crate) fn new(wire: &'a mut tls::Connection<'d, R, ID>) -> Self {
        Self { wire }
    }

    pub(crate) fn prepare<'b>(
        &mut self,
        send: send::Storage<'b, tls::SendState<'d>>,
        plain: send::Plain<'b>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Prepared<'b, reclaim::OnSubmit, send::Plain<'b>>> {
        if plain.is_empty() && send.as_slice().is_empty() && !self.wire.has_debt() {
            return end.output(send.buffered());
        }
        let mut plan = progress::Plan::plain(send, plain);
        let (send, plain) = plan.parts();
        let Some(egress) = self.wire.try_buffer(send) else {
            return end.output(plan.into_storage().buffer_wait());
        };
        if let Some(cause) = self.wire.drain(egress) {
            send.drop_empty();
            let output = self.finish(plan.finish(), true);
            return end.terminal(
                output,
                terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
            );
        }
        if self.wire.has_debt() {
            send.drop_empty();
            let close = self.wire.failed;
            let output = self.finish(plan.finish(), close);
            return end.output(output);
        }
        let sealed = self.encrypt(egress, plain, end);
        send.drop_empty();
        let close = self.wire.failed;
        let output = self.finish(plan.finish(), close);
        sealed.map(|()| output)
    }

    pub(crate) fn prepare_many<'b, const N: usize>(
        &mut self,
        send: send::Storage<'b, tls::SendState<'d>>,
        plain: send::Vectored<'b, N>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Prepared<'b, reclaim::OnSubmit, send::Plain<'b>>> {
        if plain.is_empty() && send.as_slice().is_empty() && !self.wire.has_debt() {
            return end.output(send.buffered());
        }
        let mut plan = progress::Plan::vectored(send, &plain);
        let (send, plain) = plan.parts();
        let Some(egress) = self.wire.try_buffer(send) else {
            return end.output(plan.into_storage().buffer_wait());
        };
        if let Some(cause) = self.wire.drain(egress) {
            send.drop_empty();
            let output = self.finish(plan.finish(), true);
            return end.terminal(
                output,
                terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
            );
        }
        if self.wire.has_debt() {
            send.drop_empty();
            let close = self.wire.failed;
            let output = self.finish(plan.finish(), close);
            return end.output(output);
        }
        let sealed = self.encrypt_many(egress, plain, end);
        send.drop_empty();
        let close = self.wire.failed;
        let output = self.finish(plan.finish(), close);
        sealed.map(|()| output)
    }

    fn encrypt(
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
    fn encrypt_many<const N: usize>(
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

    pub(crate) fn after_send<'b>(
        &mut self,
        done: send::Completion<'b, reclaim::OnSubmit, tls::SendState<'d>>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Transition<'b, reclaim::OnSubmit, send::Plain<'b>>> {
        let mut send = done.consume_max();
        self.wire.send_inflight = false;
        let Some(egress) = send.buffer_mut() else {
            return end.output(send::Transition::unchanged(send.buffered()));
        };
        let cause = self.wire.drain(egress);
        let close = self.wire.failed;
        let free = send.free_empty();
        let ready = self.finish(send.consume_none(), close);
        let output = send::Transition::new(ready, free);
        match cause {
            Some(cause) => end.terminal(
                output,
                terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
            ),
            None => end.output(output),
        }
    }

    pub(crate) fn settle<'b>(
        &mut self,
        done: send::Completion<'b, reclaim::OnSubmit, tls::SendState<'d>>,
        end: Option<terminal::Drain<'_, 'd, tls::Tls<R>>>,
    ) -> send::Transition<'b, reclaim::OnSubmit, send::Plain<'b>> {
        let mut send = done.consume_max();
        self.wire.send_inflight = false;
        if self.resume(&mut send, end).is_pending() {
            return send::Transition::unchanged(send.buffer_wait().close_after());
        }
        let free = send.free_empty();
        let ready = self.finish(send.consume_none(), true);
        send::Transition::new(ready, free)
    }

    pub(crate) fn flush<'b>(
        &mut self,
        mut send: send::Storage<'b, tls::SendState<'d>>,
        end: terminal::Send<'_, terminal::Error<'d, tls::Tls<R>>>,
    ) -> terminal::Processed<send::Prepared<'b, reclaim::OnSubmit, send::Plain<'b>>> {
        if send.as_slice().is_empty() && !self.wire.has_debt() {
            return end.output(send.buffered());
        }
        let Some(egress) = self.wire.try_buffer(&mut send) else {
            return end.output(send.buffer_wait());
        };
        let cause = self.wire.drain(egress);
        let close = self.wire.failed;
        send.drop_empty();
        let output = self.finish(send.consume_none(), close);
        match cause {
            Some(cause) => end.terminal(
                output,
                terminal::Terminal::Failed(terminal::Error::from_cause(cause)),
            ),
            None => end.output(output),
        }
    }

    pub(crate) fn drain<'b>(
        &mut self,
        mut send: send::Storage<'b, tls::SendState<'d>>,
        end: Option<terminal::Drain<'_, 'd, tls::Tls<R>>>,
    ) -> send::Prepared<'b, reclaim::OnSubmit, send::Plain<'b>> {
        if self.resume(&mut send, end).is_pending() {
            return send.buffer_wait().close_after();
        }
        send.drop_empty();
        self.finish(send.consume_none(), true)
    }

    fn resume(
        &mut self,
        send: &mut tls::SendState<'d>,
        end: Option<terminal::Drain<'_, 'd, tls::Tls<R>>>,
    ) -> Poll<()> {
        let Some(end) = end else {
            return Poll::Ready(());
        };
        if !self.wire.has_debt() {
            return Poll::Ready(());
        }
        let Some(egress) = self.wire.try_buffer(send) else {
            return Poll::Pending;
        };
        if let Some(cause) = self.wire.drain(egress) {
            end.fail(cause);
        }
        Poll::Ready(())
    }

    pub(crate) fn finish<'b>(
        &mut self,
        used: send::Consumed<'b, tls::SendState<'d>>,
        close: bool,
    ) -> send::Prepared<'b, reclaim::OnSubmit, send::Plain<'b>> {
        self.wire.send_inflight = !used.is_empty();
        let ready = used.buffered();
        if close { ready.close_after() } else { ready }
    }
}
