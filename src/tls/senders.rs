use dope::core::driver::route;
use dope::net::wire::{send, terminal};
use send::{progress, reclaim};
use std::task::Poll;

use crate::tls::{self, egress::Egress, roles};

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
        let sealed = Egress::new(self.wire).encrypt(egress, plain, end);
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
        let sealed = Egress::new(self.wire).encrypt_many(egress, plain, end);
        send.drop_empty();
        let close = self.wire.failed;
        let output = self.finish(plan.finish(), close);
        sealed.map(|()| output)
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
