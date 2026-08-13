use std::num;

use dope::net::wire::batch;

use crate::tls::receive;

unsafe impl batch::raw::Source for receive::Batch<'_> {
    const MAX_ITEMS: num::NonZeroUsize = match num::NonZeroUsize::new(32) {
        Some(limit) => limit,
        None => num::NonZeroUsize::MIN,
    };
    const MIN_CAPACITY: num::NonZeroUsize = match num::NonZeroUsize::new(2) {
        Some(limit) => limit,
        None => num::NonZeroUsize::MIN,
    };
}
