use o3::buffer::pool::owners;
#[doc(hidden)]
pub mod policy;
mod raw;
#[doc(hidden)]
pub mod stream;
#[doc(hidden)]
pub mod waiters;
use crate::error;
use crate::state::{buffers, direct, staged};
use crate::tls::{self, roles};
use dope::core::{driver::route, io::recv};
use dope::net::wire::receive::batch;
use o3::buffer::{pool, storage};

pub struct Batch<'a> {
    owned: Option<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'a>>>>,
    plain: Option<&'a [u8]>,
}

pub(super) struct Ingress<'s, 'd, R: roles::Protocol + 'd, ID: route::Identity + 'd> {
    conn: &'s mut tls::Connection<'d, R, ID>,
    recv: buffers::Reserve<'d>,
}
impl<'s, 'd, R: roles::Protocol + 'd, ID: route::Identity + 'd> Ingress<'s, 'd, R, ID> {
    pub(super) fn new(
        conn: &'s mut tls::Connection<'d, R, ID>,
        recv: buffers::Reserve<'d>,
    ) -> Self {
        Self { conn, recv }
    }
    pub(super) fn read_batch<'id, 'a, 'c>(
        self,
        bytes: &'a mut [u8],
        cap: batch::Grant<'id, 'c, tls::Tls<R>>,
    ) -> (
        batch::Produced<'id, Batch<'a>>,
        Result<(), error::Error>,
        buffers::Release,
    )
    where
        'd: 'a,
    {
        let mut control = (Ok(()), buffers::Release::Retained);
        let output = cap.produce(raw::Producer {
            ingress: self,
            bytes,
            control: &mut control,
        });
        (output, control.0, control.1)
    }
    pub(super) fn retain<'a>(
        self,
        bytes: recv::Lease<'a>,
    ) -> (
        Option<stream::Retained<'d, 'a>>,
        Result<(), error::Error>,
        buffers::Release,
    )
    where
        'a: 'd,
    {
        use direct::source::Cursor;
        let (
            staged::Output {
                chunk,
                control: mut failure,
                mut released,
            },
            plain,
        ) = direct::Input::owned(self.conn, bytes, self.recv);
        let output = match stream::Retained::try_new(chunk, Cursor::new(plain)) {
            Ok(output) => output,
            Err(cause) => {
                self.conn.failed = true;
                released = buffers::Release::Released;
                if failure.is_ok() {
                    failure = Err(cause);
                }
                None
            }
        };
        (output, failure, released)
    }
    fn read<B: AsMut<[u8]>>(self, bytes: B) -> (staged::Output<'d>, direct::Plain<B>) {
        direct::Input::owned(self.conn, bytes, self.recv)
    }
}
