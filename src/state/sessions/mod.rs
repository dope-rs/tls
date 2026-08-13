use shin::connection;
use shin::wire::handshake;

pub mod clients;
pub mod servers;

#[doc(hidden)]
pub trait Peer {
    fn send_pending_key_update_response_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn send_key_update_into<S: connection::EventSink + ?Sized>(
        &mut self,
        request: handshake::KeyUpdateRequest,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn note_application_data(&mut self);

    fn selected_alpn(&self) -> Option<&[u8]> {
        None
    }
}

pub(crate) trait ClientPeer: Peer {
    fn start_into<S: connection::EventSink + ?Sized>(
        &mut self,
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;

    fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}

pub(crate) trait ServerPeer: Peer {
    fn read_into<S: connection::EventSink + ?Sized>(
        &mut self,
        epoch: connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), connection::DriveError<S::Error>>;
}
