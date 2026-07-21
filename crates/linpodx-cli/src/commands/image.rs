//! Phase 18 Stream B — `linpodx image <...>` docker-compat alias of `images`.
//!
//! The existing `Cmd::Images(ImagesCmd)` variant in `main.rs` carries the
//! singular `image` name as a `clap` *visible alias*. The two surfaces share
//! a single dispatch path — there is no parallel handler — so `linpodx image
//! ls` and `linpodx images ls` behave identically.
//!
//! Keeping this file lets future per-noun extensions (e.g. an `image build`
//! subcommand that does not belong on the plural form) land here without
//! a second main.rs edit. Today the file is intentionally documentation
//! only; nothing is re-exported.
#![forbid(unsafe_code)]
