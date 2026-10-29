use dope::net::wire::receive::batch::{Capacity, Spare};
use dope_tls::tls::{Tls, roles::Server};
use std::mem;

type Wire = Tls<Server>;

#[test]
fn clamps_batch() {
    assert_eq!(
        mem::size_of::<Capacity<'_, Wire>>(),
        mem::size_of::<usize>()
    );
    assert!(Capacity::<Wire>::fit_spare(Spare::from_usize(0)).is_none());
    let pair = Capacity::<Wire>::fit_spare(Spare::from_usize(1)).expect("minimum capacity");
    assert_eq!(pair.items().get(), 2);
    let full = Capacity::<Wire>::fit_spare(Spare::from_usize(usize::MAX)).expect("full capacity");
    assert_eq!(full.items().get(), 2);
}
