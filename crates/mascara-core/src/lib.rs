//! mascara-core — the pure heart of Mascara: identity, contact card, keystore (M0); ticket
//! seal/open, the issued-ticket registry, and verify-only `link_assertion` (M1); the serve-time
//! source check (M2); manifests, content-check, history follow (M3+). See `DESIGN.md` §1 for the
//! crate's place in the workspace and `MASCARA_SPEC.md` for the invariants it exists to uphold.
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

pub mod assertion;
pub mod card;
pub mod content_check;
pub mod error;
pub mod history;
pub mod identity;
pub mod keystore;
pub mod manifest;
pub mod registry;
pub mod share;
pub mod source;
pub mod ticket;

pub use assertion::LinkAssertion;
pub use card::Card;
pub use content_check::{check as check_content, Policy as ContentPolicy, Verdict as ContentVerdict};
pub use error::CoreError;
pub use history::{
    History, HistoryConfig, HistoryLog, HistoryRecord, HistoryStore, TransferId, TransferState,
    HISTORY_VERSION,
};
pub use identity::Identity;
pub use manifest::{
    decode as decode_manifest, decode_and_verify as decode_and_verify_manifest,
    encode as encode_manifest, root_hash as manifest_root_hash, verify as verify_manifest,
    DecodeOutcome, Manifest, ManifestEntry, HARD_CAP_BYTES as MANIFEST_HARD_CAP_BYTES,
    MANIFEST_VERSION, SOFT_WARN_BYTES as MANIFEST_SOFT_WARN_BYTES,
};
pub use registry::{FileStore, IssuedRecord, IssuedStore, IssuedTickets, Registry};
pub use share::{FileDescriptor, FolderDescriptor, FolderEntry, ShareDescriptor};
pub use source::{check_source, SourceCheck};
pub use ticket::{Endpoint, FileRef, FolderRef, Grant, Kind, Nonce, Payload, Ticket};
