pub mod fiber;
pub mod native;
mod read;
pub use read::Read;
pub mod reply;
pub mod retry;
mod signer;
pub use signer::Signer;
pub mod state;
pub mod times;

pub fn recover(
    failure: dope::core::driver::life::recovery::Recovery<'_, '_>,
) -> std::convert::Infallible {
    panic!("native recovery: {:?}", failure.cause())
}
