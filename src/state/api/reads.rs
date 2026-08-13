use crate::error;
use crate::state::Internals as _;
use crate::state::{self, direct, sessions, staged};

pub trait Client<'d> {
    fn read_tcp(&mut self, bytes: &[u8], receive: impl FnMut(&[u8])) -> Result<(), error::Error>;

    #[doc(hidden)]
    fn read_tcp_in_place<'a>(&mut self, bytes: &'a mut [u8]) -> direct::WireRead<'a>;

    #[doc(hidden)]
    fn read_staged_wire(&mut self, bytes: &[u8]) -> staged::WireRead<'d>;

    fn try_read_tcp(&mut self, bytes: &[u8], receive: impl FnMut(&[u8])) -> bool;
}

pub trait Server<'d> {
    fn read_tcp(&mut self, bytes: &[u8], receive: impl FnMut(&[u8])) -> Result<(), error::Error>;

    #[doc(hidden)]
    fn read_tcp_in_place<'a>(&mut self, bytes: &'a mut [u8]) -> direct::WireRead<'a>;

    #[doc(hidden)]
    fn read_staged_wire(&mut self, bytes: &[u8]) -> staged::WireRead<'d>;

    fn try_read_tcp(&mut self, bytes: &[u8], receive: impl FnMut(&[u8])) -> bool;
}

impl<'d, S: sessions::ClientPeer> Client<'d> for state::State<'d, S> {
    fn read_tcp(
        &mut self,
        bytes: &[u8],
        mut receive: impl FnMut(&[u8]),
    ) -> Result<(), error::Error> {
        let read = staged::Reader::new(self).read(
            bytes,
            &mut |session, epoch, data, events| session.read_into(epoch, data, events),
            &mut receive,
        );
        let drained = self.drain_pending_control();
        read?;
        drained
    }

    fn read_tcp_in_place<'a>(&mut self, bytes: &'a mut [u8]) -> direct::WireRead<'a> {
        let mut read = direct::Reader::new(self)
            .read_in_place(bytes, &mut |session, epoch, data, events| {
                session.read_into(epoch, data, events)
            });
        if self.drain_pending_control().is_err() {
            read.fail();
        }
        read
    }

    fn read_staged_wire(&mut self, bytes: &[u8]) -> staged::WireRead<'d> {
        let mut read = staged::Reader::new(self)
            .read_one_wire(bytes, &mut |session, epoch, data, events| {
                session.read_into(epoch, data, events)
            });
        if self.drain_pending_control().is_err() {
            read.fail();
        }
        read
    }

    fn try_read_tcp(&mut self, bytes: &[u8], receive: impl FnMut(&[u8])) -> bool {
        bytes.is_empty() || Client::read_tcp(self, bytes, receive).is_ok()
    }
}

impl<'d, S: sessions::ServerPeer> Server<'d> for state::State<'d, S> {
    fn read_tcp(
        &mut self,
        bytes: &[u8],
        mut receive: impl FnMut(&[u8]),
    ) -> Result<(), error::Error> {
        let read = staged::Reader::new(self).read(
            bytes,
            &mut |session, epoch, data, events| session.read_into(epoch, data, events),
            &mut receive,
        );
        let drained = self.drain_pending_control();
        read?;
        drained
    }

    fn read_tcp_in_place<'a>(&mut self, bytes: &'a mut [u8]) -> direct::WireRead<'a> {
        let mut read = direct::Reader::new(self)
            .read_in_place(bytes, &mut |session, epoch, data, events| {
                session.read_into(epoch, data, events)
            });
        if self.drain_pending_control().is_err() {
            read.fail();
        }
        read
    }

    fn read_staged_wire(&mut self, bytes: &[u8]) -> staged::WireRead<'d> {
        let mut read = staged::Reader::new(self)
            .read_one_wire(bytes, &mut |session, epoch, data, events| {
                session.read_into(epoch, data, events)
            });
        if self.drain_pending_control().is_err() {
            read.fail();
        }
        read
    }

    fn try_read_tcp(&mut self, bytes: &[u8], receive: impl FnMut(&[u8])) -> bool {
        bytes.is_empty() || Server::read_tcp(self, bytes, receive).is_ok()
    }
}
