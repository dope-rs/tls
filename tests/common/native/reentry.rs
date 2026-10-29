use std::{
    alloc::{GlobalAlloc, Layout},
    cell::{BorrowError, Cell, RefCell},
    sync::Arc,
};

use dope::{
    core::driver::route::KeyTag,
    net::{
        Resource,
        wire::domain::{Bootstrap as _, Limits},
    },
};
use dope_test::alloc::Tracker;
use dope_tls::tls::{
    endpoint::{self, layout::Staged},
    protocol::Bootstrap,
    roles,
};

pub struct Context {
    pub sessions: endpoint::Sessions<roles::Server>,
    pub config: Arc<rustls::ServerConfig>,
}

thread_local! {
    pub static CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) };
    static ARMED: Cell<State> = const { Cell::new(State::Idle) };
}

#[derive(Debug)]
pub enum Error {
    Borrow(BorrowError),
    Missing,
    Binding(Resource),
}

enum State {
    Idle,
    After(usize),
    Complete(Result<(), Error>),
}

pub struct Reentrant;

impl Reentrant {
    pub fn on_alloc<T>(after: usize, run: impl FnOnce() -> T) -> (T, Option<Result<(), Error>>) {
        let previous = ARMED.replace(State::After(after));
        let value = run();
        let result = match ARMED.replace(previous) {
            State::Complete(result) => Some(result),
            State::Idle | State::After(_) => None,
        };
        (value, result)
    }

    fn before() {
        let state = match ARMED.replace(State::Idle) {
            State::After(0) => State::Complete(CONTEXT.with(|owner| {
                let owner = owner.try_borrow().map_err(Error::Borrow)?;
                let owner = owner.as_ref().ok_or(Error::Missing)?;
                Bootstrap::<roles::Server>::try_runtime::<KeyTag<0>>(
                    Limits::fixed::<1, 0, 0, { 64 * 1024 }>(),
                    endpoint::Config::from(owner.config.clone())
                        .with_staged(Staged::fixed::<0>())
                        .bind(&owner.sessions),
                )
                .map(drop)
                .map_err(Error::Binding)
            })),
            State::After(after) => State::After(after - 1),
            state => state,
        };
        ARMED.set(state);
    }
}

// SAFETY: every pointer and layout is forwarded unchanged to Tracker. The arm
// is cleared before binding, so its allocations cannot recursively invoke it.
unsafe impl GlobalAlloc for Reentrant {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::before();
        unsafe { Tracker.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::before();
        unsafe { Tracker.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { Tracker.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        Self::before();
        unsafe { Tracker.realloc(pointer, layout, size) }
    }
}
