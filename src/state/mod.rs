use crate::error;
use o3::buffer::{pool, write};
use std::io;

pub(crate) mod buffers;
pub(crate) mod direct;
pub(crate) mod staged;

struct Output<'a>(write::Spare<'a>);
impl io::Write for Output<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(self.0.write(bytes))
    }
    fn write_vectored(&mut self, chunks: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let mut written = 0;
        for bytes in chunks {
            let n = self.0.write(bytes);
            written += n;
            if n != bytes.len() {
                break;
            }
        }
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn drain(
    conn: &mut rustls::Connection,
    out: &mut pool::Cursor<pool::Layout, pool::Borrowed<'_>>,
) -> Result<(), error::Error> {
    if !conn.wants_write() {
        return Ok(());
    }
    let mut output = Output(out.spare());
    let result = loop {
        if output.0.remaining() == 0 {
            break Ok(());
        }
        match conn.write_tls(&mut output) {
            Ok(0) => break Err(error::Error::InvalidBufferProgress),
            Ok(_) if !conn.wants_write() => break Ok(()),
            Ok(_) => {}
            Err(cause) => break Err(error::Error::Io(cause)),
        }
    };
    output.0.commit();
    result
}
