//! Errors surfaced by the relay client. A hostile relay is an adversary (AB8), so every
//! reason is carried explicitly — a silent drop or an `OK: false` must be observable, never
//! swallowed — and untrusted relay/wire input never panics.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetError {
    /// No relay in the configured set completed the websocket handshake within the timeout.
    #[error("no relay connected: {0}")]
    NoRelayConnected(String),

    /// Every relay rejected the publish (explicit `OK: false`) or silently dropped it.
    #[error("publish accepted by no relay: {0}")]
    PublishRejected(String),

    /// A discovery query that constrains nothing (empty tags AND empty content-types) is
    /// rejected before any relay round-trip (DISC4) — an unbounded fetch is never issued.
    #[error("empty filter: a query must constrain at least one tag or content-type")]
    EmptyFilter,

    /// A NIP-65 / NIP-17 / relay-frame decoder rejected malformed or untrusted input.
    #[error("invalid relay list: {0}")]
    InvalidRelayList(String),

    /// A gift-wrapped DM could not be unwrapped (not addressed to us, tampered, or malformed).
    #[error("DM unwrap failed: {0}")]
    DmUnwrap(String),

    /// The oversize-listing split / restitch protocol failed (malformed index or missing part).
    #[error("listing split error: {0}")]
    Split(String),

    /// Transport-level failure from the underlying relay client.
    #[error("relay client error: {0}")]
    Client(String),

    /// An hb-core builder/parser rejected the event (bad signature, version, or shape).
    #[error(transparent)]
    Core(#[from] hb_core::HbError),
}
