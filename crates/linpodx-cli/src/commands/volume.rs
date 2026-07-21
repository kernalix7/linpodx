//! Phase 18 Stream B — `linpodx volumes <...>` docker-compat plural alias.
//!
//! `Cmd::Volume(VolumeCmd)` in `main.rs` already lives at the singular
//! `volume` path; the plural form `volumes` is attached as a `clap` visible
//! alias. Both forms dispatch through the same `handle_volume` handler — no
//! parallel implementation, no behavior delta.
//!
//! This file exists as the documented landing zone for any future
//! `volume`-only or `volumes`-only verbs we might want to keep off the
//! shared enum. It is intentionally documentation only today.
#![forbid(unsafe_code)]
