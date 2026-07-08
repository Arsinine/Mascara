//! mascara-core — the pure heart of Mascara: identity, contact card, keystore (M0); tickets,
//! manifests, content-check, registry, history follow (M1+). See `DESIGN.md` §1 for the crate's
//! place in the workspace and `MASCARA_SPEC.md` for the invariants it exists to uphold.
//!
//! **No network I/O lives here.** iroh, the protocol engine, and everything async belong to
//! `mascara-net`; the GUI/CLI sit above that. This crate is synchronous and heavily unit-tested,
//! the same division of labor Hoardbook proved with `hb-core`.
//!
//! **MAS-INV-1 (separate identity).** The identity minted here is Mascara's OWN — never the
//! Hoardbook `npub`, never derived from it, never publicly bound to it. Two independent keypairs
//! under one card (spec D10):
//! - an **ed25519 transport key** — the iroh endpoint identity a receiver pins before dialing
//!   (`mascara-net` builds the iroh `SecretKey` from these raw bytes, keeping this crate
//!   network-free);
//! - an **X25519 sealing key** — what a sender encrypts transfer tickets to (age-style HPKE).

pub mod card;
pub mod error;
pub mod identity;
pub mod keystore;

pub use card::Card;
pub use error::CoreError;
pub use identity::Identity;
