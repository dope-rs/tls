use std::{
    cell::Cell,
    convert,
    io::{self, Read as _},
    net::Shutdown,
    pin::Pin,
};

use dope::core::{
    driver::{
        retained::Context,
        route::{Identity, KeyTag},
        schedule::{clock, ready},
    },
    io::socket,
    random::Seed,
};
use dope::{
    manifold::{
        app::{
            env::Bundle,
            receive::{Borrowed, End, Outcome},
        },
        network::listener::{
            Listener, conn,
            handler::{self, Application, failures, retire, send},
        },
        timing,
    },
    net::{
        link::egress::{self, load::Value},
        tcp::Tcp,
        wire::{open, terminal},
    },
};
use dope_test::harness::{peer, signals::Gate};
use dope_tls::tls::{Tls, roles::Server};
use o3::{
    base::Call,
    buffer::{
        bytes::TryRetain,
        resident,
        storage::{self, Shared},
    },
};

use conn::write::{self, error};

use crate::common::fiber::{Connect, Peer};

type Wire = Tls<Server>;

pub const LEN: usize = 50_000;
pub const PREFIX: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
const START: &[u8] = b"start";
const AFTER: &[u8] = b"after";

#[derive(Clone, Copy)]
pub enum Mode {
    Close,
    Local,
    Peer,
}

pub struct Reply<'r> {
    pub body: Vec<u8>,
    pub closes: Gate,
    pub observe: &'r dyn for<'d> Fn(Event<'d>),
    pub mode: Mode,
}

pub enum Event<'d> {
    Open(dope_tls::Error),
    Wire((dope_tls::Error, Option<dope_tls::Error>)),
    Peer(socket::Error),
    Copy(storage::AllocError),
    Write(Result<write::Outcome<()>, error::Error<resident::Shared<'d>, (), convert::Infallible>>),
    Input(Vec<u8>),
    Eof(bool),
}

impl Reply<'_> {
    fn reply<'d, ID: Identity>(
        &self,
        conn: &mut conn::Ctx<'_, '_, '_, '_, '_, 'd, ID, Wire, bool>,
        driver: &mut Context<'_, '_, 'd>,
    ) {
        let bytes = match Shared::try_copy(&self.body) {
            Ok(bytes) => bytes,
            Err(cause) => {
                (self.observe)(Event::Copy(cause));
                conn.close_after();
                return;
            }
        };
        let body = egress::Load::new(resident::Shared::from(bytes));
        let result = conn.write().try_bounded(driver, move |_, prefix| {
            prefix[..PREFIX.len()].copy_from_slice(PREFIX);
            write::Draft::new(PREFIX.len(), Some(Value::Unchecked(body)), ())
        });
        (self.observe)(Event::Write(result));
    }
}

impl<'d, ID: Identity> Application<'d, ID> for Reply<'_> {
    type Conn = bool;
    type Build = convert::Infallible;
    type Wire = Wire;
    type WireFailure = Self;
    type Retirement = retire::Close;
    type Egress = resident::Shared<'d>;
    type Input = Borrowed;
    type Send = send::Silent;

    fn connection(self: Pin<&Self>, _: &Seed) -> Result<Self::Conn, Self::Build> {
        Ok(false)
    }

    fn build_failed(self: Pin<&mut Self>, cause: Self::Build) {
        match cause {}
    }

    fn deadline(self: Pin<&Self>, _: clock::Clock<'_, 'd>) -> Option<clock::Deadline<'d>> {
        None
    }

    fn eof(
        self: Pin<&mut Self>,
        mut conn: conn::Ctx<'_, '_, '_, '_, '_, 'd, ID, Wire, bool>,
        _: End,
        driver: &mut Context<'_, '_, 'd>,
    ) -> handler::Eof {
        let this = self.get_mut();
        (this.observe)(Event::Eof(*conn.state()));
        if matches!(this.mode, Mode::Peer) {
            this.reply(&mut conn, driver);
            conn.close_after();
            handler::Eof::Hold
        } else {
            handler::Eof::Close
        }
    }

    fn close<'e, 'a, 'p, 's, 'w>(
        self: Pin<&mut Self>,
        conn: conn::Ctx<'e, 'a, 'p, 's, 'w, 'd, ID, Wire, bool>,
    ) -> conn::Ctx<'e, 'a, 'p, 's, 'w, 'd, ID, Wire, bool>
    where
        'd: 'w,
    {
        self.get_mut().closes.hit();
        conn
    }
}

impl<'r, 'w, 'd: 'w, ID: Identity> failures::Policy<'w, 'd, Reply<'r>, ID> for Reply<'r> {
    fn open_failed(app: Pin<&mut Reply<'r>>, cause: open::Error<'w, Wire>) {
        (app.get_mut().observe)(Event::Open(cause.into_cause()));
    }

    fn peer() -> Option<impl for<'a> Call<(Pin<&'a mut Reply<'r>>, socket::Error)>> {
        Some(|(app, cause): (Pin<&mut Reply<'r>>, socket::Error)| {
            (app.get_mut().observe)(Event::Peer(cause));
        })
    }

    fn wire_failed<'e>(
        app: Pin<&mut Reply<'r>>,
        _: conn::Ctx<'e, '_, '_, '_, 'w, 'd, ID, Wire, bool>,
        cause: terminal::Error<'w, Wire>,
    ) {
        (app.get_mut().observe)(Event::Wire(cause.into_parts()));
    }
}

impl<'d, ID: Identity> handler::Borrowed<'d, ID> for Reply<'_> {
    fn chunk<R: TryRetain>(
        self: Pin<&mut Self>,
        mut conn: conn::Ctx<'_, '_, '_, '_, '_, 'd, ID, Wire, bool>,
        chunk: R,
        driver: &mut Context<'_, '_, 'd>,
    ) -> Outcome {
        let this = self.get_mut();
        (this.observe)(Event::Input(chunk.as_ref().to_vec()));
        if *conn.state() {
            return Outcome::CloseAfter;
        }
        *conn.state_mut() = true;
        match this.mode {
            Mode::Close => {
                this.reply(&mut conn, driver);
                Outcome::CloseAfter
            }
            Mode::Local => {
                this.reply(&mut conn, driver);
                conn.shutdown();
                Outcome::Continue
            }
            Mode::Peer => Outcome::Continue,
        }
    }
}

pub struct Capacity<'r, 'd> {
    pub reply: Reply<'r>,
    pub targets: &'r Cell<[Option<ready::Target<'d>>; 2]>,
    pub armed: &'r Cell<bool>,
    pub ready: Gate,
    pub observe: &'r dyn Fn(Change<'_>),
}

pub enum Change<'a> {
    Ready(egress::Pending),
    Activated,
    Released {
        index: usize,
        body: &'a [u8],
        cause: handler::Disposition,
    },
}

impl<'d> Application<'d, KeyTag<0>> for Capacity<'_, 'd> {
    type Conn = bool;
    type Build = convert::Infallible;
    type Wire = Wire;
    type WireFailure = Self;
    type Retirement = retire::Close;
    type Egress = resident::Shared<'d>;
    type Input = Borrowed;
    type Send = send::Reported<send::Silent>;

    fn connection(self: Pin<&Self>, _: &Seed) -> Result<Self::Conn, Self::Build> {
        Ok(false)
    }

    fn build_failed(self: Pin<&mut Self>, cause: Self::Build) {
        match cause {}
    }

    fn deadline(self: Pin<&Self>, _: clock::Clock<'_, 'd>) -> Option<clock::Deadline<'d>> {
        None
    }

    fn activate<'e, 'a, 'p, 's, 'w>(
        self: Pin<&mut Self>,
        mut conn: conn::Ctx<'e, 'a, 'p, 's, 'w, 'd, KeyTag<0>, Wire, bool>,
        driver: &mut Context<'_, '_, 'd>,
    ) -> conn::Ctx<'e, 'a, 'p, 's, 'w, 'd, KeyTag<0>, Wire, bool>
    where
        'd: 'w,
    {
        let this = self.get_mut();
        if this.armed.get() && !*conn.state() {
            *conn.state_mut() = true;
            this.reply.reply(&mut conn, driver);
            (this.observe)(Change::Activated);
            conn.close_after();
        }
        conn
    }

    fn close<'e, 'a, 'p, 's, 'w>(
        self: Pin<&mut Self>,
        conn: conn::Ctx<'e, 'a, 'p, 's, 'w, 'd, KeyTag<0>, Wire, bool>,
    ) -> conn::Ctx<'e, 'a, 'p, 's, 'w, 'd, KeyTag<0>, Wire, bool>
    where
        'd: 'w,
    {
        self.get_mut().reply.closes.hit();
        conn
    }
}

impl<'r, 'w, 'd: 'w> failures::Policy<'w, 'd, Capacity<'r, 'd>, KeyTag<0>> for Capacity<'r, 'd> {
    fn open_failed(app: Pin<&mut Capacity<'r, 'd>>, cause: open::Error<'w, Wire>) {
        (app.get_mut().reply.observe)(Event::Open(cause.into_cause()));
    }

    fn peer() -> Option<impl for<'a> Call<(Pin<&'a mut Capacity<'r, 'd>>, socket::Error)>> {
        Some(
            |(app, cause): (Pin<&mut Capacity<'r, 'd>>, socket::Error)| {
                (app.get_mut().reply.observe)(Event::Peer(cause));
            },
        )
    }

    fn wire_failed<'e>(
        app: Pin<&mut Capacity<'r, 'd>>,
        _: conn::Ctx<'e, '_, '_, '_, 'w, 'd, KeyTag<0>, Wire, bool>,
        cause: terminal::Error<'w, Wire>,
    ) {
        (app.get_mut().reply.observe)(Event::Wire(cause.into_parts()));
    }
}

impl<'d> handler::Borrowed<'d, KeyTag<0>> for Capacity<'_, 'd> {
    fn chunk<R: TryRetain>(
        self: Pin<&mut Self>,
        mut conn: conn::Ctx<'_, '_, '_, '_, '_, 'd, KeyTag<0>, Wire, bool>,
        chunk: R,
        _: &mut Context<'_, '_, 'd>,
    ) -> Outcome {
        let this = self.get_mut();
        (this.reply.observe)(Event::Input(chunk.as_ref().to_vec()));
        (this.observe)(Change::Ready(conn.write().pending()));
        let mut targets = this.targets.get();
        targets[conn.id().index().into_usize()] = Some(conn.wake_target());
        this.targets.set(targets);
        this.ready.hit();
        Outcome::Continue
    }
}

impl<'d> send::Report<'d, KeyTag<0>> for Capacity<'_, 'd> {
    const ENABLED: bool = true;

    fn released(self: Pin<&mut Self>, release: handler::Release<'d, KeyTag<0>, Self::Egress>) {
        let (id, body, cause) = release.into_parts();
        (self.get_mut().observe)(Change::Released {
            index: id.index().into_usize(),
            body: body.as_ref(),
            cause,
        });
    }
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
pub struct App<'r, 'n, 'p, 's, 'w, 'd: 's + 'w> {
    #[pin]
    #[manifold]
    pub listener:
        Listener<'n, 'p, 's, 'w, 'd, KeyTag<0>, Reply<'r>, Bundle<Tcp, Wire, timing::Throughput>>,
}

#[derive(Default)]
pub struct Records {
    pub tail: Vec<u8>,
    pub count: usize,
}

impl Records {
    pub fn push(&mut self, bytes: &[u8]) {
        self.tail.extend_from_slice(bytes);
        let mut used = 0;
        while self.tail.len() - used >= 5 {
            let body = u16::from_be_bytes([self.tail[used + 3], self.tail[used + 4]]) as usize;
            let len = 5 + body;
            if self.tail.len() - used < len {
                break;
            }
            used += len;
            self.count += 1;
        }
        self.tail.drain(..used);
    }
}

fn shut(peer: &mut Peer<'_>) -> Result<(), Connect> {
    peer.tls.send_close_notify();
    while peer.tls.wants_write() {
        let used = peer.tls.write_tls(&mut peer.socket).map_err(Connect::Io)?;
        if used == 0 {
            return Err(Connect::Io(io::ErrorKind::WriteZero.into()));
        }
    }
    Ok(())
}

pub fn run_client(
    socket: &peer::Stream<'_>,
    pubkey: [u8; 32],
    mode: Mode,
) -> Result<(bool, Vec<u8>, Records), Connect> {
    let mut peer = Peer::establish(socket, pubkey)?;
    peer.try_send(START)?;
    if matches!(mode, Mode::Peer) {
        shut(&mut peer)?;
    }

    receive(peer, mode)
}

pub fn run_pair(
    sockets: &mut [&peer::Stream<'_>; 2],
    pubkey: [u8; 32],
) -> Result<[(bool, Vec<u8>, Records); 2], Connect> {
    let mut first = Peer::establish(sockets[0], pubkey)?;
    first.try_send(START)?;
    let mut second = Peer::establish(sockets[1], pubkey)?;
    second.try_send(START)?;
    Ok([receive(first, Mode::Close)?, receive(second, Mode::Close)?])
}

fn receive(mut peer: Peer<'_>, mode: Mode) -> Result<(bool, Vec<u8>, Records), Connect> {
    let mut got = Vec::new();
    let mut frames = Records::default();
    let mut input = [0u8; 16 * 1024];
    let mut closed = false;
    loop {
        let read = peer.socket.read(&mut input).map_err(Connect::Io)?;
        frames.push(&input[..read]);
        let mut bytes = &input[..read];
        loop {
            let used = peer.tls.read_tls(&mut bytes).map_err(Connect::Io)?;
            if used != 0 {
                closed |= peer
                    .tls
                    .process_new_packets()
                    .map_err(Connect::Tls)?
                    .peer_has_closed();
            }
            match peer.tls.reader().read_to_end(&mut got) {
                Ok(_) => {}
                Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => {}
                Err(cause) => return Err(Connect::Io(cause)),
            }
            if bytes.is_empty() || used == 0 {
                break;
            }
        }
        if read == 0 {
            break;
        }
    }
    if matches!(mode, Mode::Local) {
        peer.try_send(AFTER)?;
        shut(&mut peer)?;
        peer.socket.shutdown(Shutdown::Write).map_err(Connect::Io)?;
    }
    Ok((closed, got, frames))
}
