//! Phase 18 Stream B — `linpodx networks <...>` docker-compat plural alias.
//!
//! `Cmd::Network(NetworkCmd)` in `main.rs` already lives at the singular
//! `network` path; the plural form `networks` is attached as a `clap`
//! visible alias. Both forms dispatch through the same `handle_network`
//! handler — no parallel implementation, no behavior delta.
//!
//! This file exists as the documented landing zone for any future
//! `network`-only or `networks`-only verbs. It is intentionally
//! documentation only today.
#![forbid(unsafe_code)]
