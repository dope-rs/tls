//! Thin forwarders into dope's per-thread `MemStats` for the three TLS staging
//! boxes (egress, recv_buf, pending_send). Gated on `mem-stats`; with the feature
//! off every fn is empty and compiles to nothing.

/// Emit the active and inert arm from one list so the two can't drift.
macro_rules! tls_counters {
    ($($fwd:ident => $dope_fn:path),* $(,)?) => {
        cfg_select! {
            feature = "mem-stats" => {
                $( pub(crate) fn $fwd() { $dope_fn(); } )*
            }
            _ => {
                $( pub(crate) fn $fwd() {} )*
            }
        }
    };
}

tls_counters! {
    egress_borrow  => dope::memstats::tls_egress_borrow,
    egress_release => dope::memstats::tls_egress_release,
    recv_borrow    => dope::memstats::tls_recv_borrow,
    recv_release   => dope::memstats::tls_recv_release,
    send_borrow    => dope::memstats::tls_send_borrow,
    send_release   => dope::memstats::tls_send_release,
}
