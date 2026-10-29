//! ```compile_fail,E0603
//! struct Foreign;
//! impl dope_tls::tls::roles::Protocol for Foreign {
//!     type Config = ();
//!     const SEND_ON_OPEN: bool = false;
//!     fn open(_: &(), _: dope_tls::tls::roles::contract::Contract)
//!         -> Result<dope_tls::rustls::Connection, dope_tls::Error> {
//!         unreachable!("foreign")
//!     }
//! }
//! ```

//! ```compile_fail,E0603
//! use dope_tls::tls::{client::Plan, roles::{Client, Protocol}};
//! fn escape(plan: &Plan)
//!     -> Result<dope_tls::rustls::Connection, dope_tls::Error> {
//!     Client::open(plan, dope_tls::tls::roles::contract::Contract(()))
//! }
//! ```

//! ```compile_fail,E0061
//! use dope_tls::tls::{client::Plan, roles::{Client, Protocol}};
//! fn escape(plan: &Plan)
//!     -> Result<dope_tls::rustls::Connection, dope_tls::Error> {
//!     Client::open(plan)
//! }
//! ```

//! ```compile_fail,E0061
//! use dope_tls::tls::roles::Protocol;
//! fn escape<R: Protocol>(config: &R::Config)
//!     -> Result<dope_tls::rustls::Connection, dope_tls::Error> {
//!     R::open(config)
//! }
//! ```

//! ```compile_fail
//! use dope_tls::tls::Connection;
//! fn escape<'a>(value: Connection<'a>) -> Connection<'static> {
//!     value
//! }
//! ```

//! ```compile_fail
//! use dope_tls::tls::SendState;
//! fn escape<'a>(value: SendState<'a>) -> SendState<'static> {
//!     value
//! }
//! ```

//! ```compile_fail
//! use dope_tls::tls::endpoint::Bound;
//! fn escape<'a>(value: Bound<'a>) -> Bound<'static> {
//!     value
//! }
//! ```

//! ```compile_fail
//! use dope::core::driver::route::KeyTag;
//! use dope_tls::tls::{endpoint::Runtime, roles::Client};
//! fn worker<'w>(value: Runtime<'w, 'static, Client, KeyTag<0>>)
//!     -> Runtime<'static, 'static, Client, KeyTag<0>> {
//!     value
//! }
//! ```

//! ```compile_fail
//! use dope::core::driver::route::KeyTag;
//! use dope_tls::tls::{endpoint::Runtime, roles::Client};
//! fn driver<'w, 'd: 'w>(value: Runtime<'w, 'd, Client, KeyTag<0>>)
//!     -> Runtime<'w, 'static, Client, KeyTag<0>> {
//!     value
//! }
//! ```

//! ```compile_fail
//! use dope_tls::tls::receive::stream::Retained;
//! fn wire<'w, 'd>(value: Retained<'w, 'd>) -> Retained<'static, 'd> {
//!     value
//! }
//! ```

//! ```compile_fail
//! use dope_tls::tls::receive::stream::Retained;
//! fn driver<'w, 'd>(value: Retained<'w, 'd>) -> Retained<'w, 'static> {
//!     value
//! }
//! ```

trait Local<A> {
    type Proof;
}

impl<T: ?Sized> Local<()> for T {
    type Proof = ();
}
impl<T: ?Sized + Send> Local<u8> for T {
    type Proof = ();
}
impl<T: ?Sized + Sync> Local<u16> for T {
    type Proof = ();
}

#[test]
fn ownership_contracts() {
    use dope::core::driver::route::KeyTag;
    use dope_tls::config::raw::Identity;
    use dope_tls::tls::{
        Connection, SendState,
        client::Plan,
        endpoint::{Bound, Config, Runtime, Sessions},
        receive::stream::Retained,
        roles::{Client, Server},
    };
    let _: <Identity as Local<_>>::Proof;
    let _: <Plan as Local<_>>::Proof;
    let _: <Config<Client> as Local<_>>::Proof;
    let _: <Config<Server> as Local<_>>::Proof;
    let _: <Sessions<Client> as Local<_>>::Proof;
    let _: <Bound<'static, Client> as Local<_>>::Proof;
    let _: <Runtime<'static, 'static, Client, KeyTag<0>> as Local<_>>::Proof;
    let _: <Connection<'static> as Local<_>>::Proof;
    let _: <SendState<'static> as Local<_>>::Proof;
    let _: <Retained<'static, 'static> as Local<_>>::Proof;

    use std::env;

    use dope_test::checks::Suite;
    let suite = Suite::new(
        env!("CARGO_MANIFEST_DIR"),
        file!(),
        &["dope-tls", "dope", "o3"],
    );
    let exe = env::current_exe().expect("test executable");
    let status = suite
        .try_build(&exe, env!("CARGO_PKG_NAME"))
        .expect("build command")
        .status()
        .expect("build original library");
    assert!(status.success(), "build original library: {status}");
    assert_eq!(
        suite
            .try_errors(&exe, include_str!("contracts.rs"))
            .expect("exact compiler errors"),
        4
    );
    let status = suite
        .try_rustdoc(&exe)
        .expect("rustdoc command")
        .status()
        .expect("compiler contracts");
    assert!(status.success(), "TLS ownership contracts: {status}");
}
