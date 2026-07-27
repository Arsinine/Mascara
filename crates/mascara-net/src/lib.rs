//! mascara-net — the iroh endpoint and the `/mascara/xfer/1` protocol engine (DESIGN.md §1/§4).
//! M2: single-file `download` transfer, duplex-tested + real iroh on LAN. See `MASCARA_SPEC.md`
//! for the invariants this crate exists to uphold, and `DESIGN.md` §4 (protocol), §5 (consent),
//! §6 (direct-only) for the shape.
//!
//! Dependency direction: `mascara-cli`/`mascara-app` → `mascara-net` → `mascara-core`. Nothing in
//! `mascara-core` touches the network; nothing here touches a UI toolkit — progress and consent
//! flow through plain callbacks/types (`engine::pull_file`'s `on_progress`, `consent::ConsentAck`).
//!
//! Modules (DESIGN §1):
//! - [`endpoint`] — build the iroh `Endpoint` (discovery off both directions BY CONSTRUCTION,
//!   relay disabled — MAS-INV-3/D1), and the ticket `Endpoint` ↔ iroh `EndpointAddr` mapping.
//! - [`listener`] — the `serve` accept loop and the server side of `/mascara/xfer/1`: the DESIGN
//!   §4 auth predicate as a pure, unit-testable function, plus the per-stream request handler.
//! - [`dialer`] — open ticket → consent gate → dial, pinning the ticket's sender-card transport key.
//! - [`engine`] — the client-side single-file pull: incremental SHA-256, progress callback,
//!   collision-safe renames, the hash-gate that makes a file "available".
//! - [`consent`] — MAS-INV-4 made structural: `ConsentAck` is constructible only via
//!   `consent::acknowledge_ip_exposure()`.

pub mod consent;
pub mod dialer;
pub mod endpoint;
pub mod engine;
pub mod error;
pub mod listener;

pub use consent::ConsentAck;
pub use error::NetError;
