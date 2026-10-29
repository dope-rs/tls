# 博

TCP TLS streams for the dope runtime, backed by rustls and AWS-LC.

Use one native TLS configuration per worker. Keep its `Arc` clones on that worker.

Rustls 0.23.46 can panic in debug builds on malformed input after local
`close_notify`; see `tests/rustls_close.rs` for the release regression.

© 2026 inkyu
