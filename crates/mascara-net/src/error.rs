//! Crate error type. One enum, reasoned variants — mirrors `mascara-core`'s `CoreError` discipline
//! (recognise-and-refuse, never a panic — Suite MAB) so the CLI can surface these verbatim.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    /// A `mascara-core` operation failed (ticket open, registry, source check).
    #[error("{0}")]
    Core(#[from] mascara_core::CoreError),

    /// An underlying I/O or stream failure — includes a QUIC stream breaking mid-transfer.
    /// **Peer-side by convention:** a partial download survives this class (the stream broke; the
    /// bytes on disk are still good — DESIGN §6.2 resume). Local filesystem failures use
    /// [`NetError::LocalIo`] instead, so the two can be told apart when deciding a `.part`'s fate.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A LOCAL filesystem failure while landing a download — creating/writing/flushing the
    /// `.part`, or renaming it into place (disk full, permission denied, a vanished directory).
    /// Distinct from [`NetError::Io`] because it is **not** a resumable condition: retrying the
    /// same broken local state would fail the same way, so the partial is discarded (codex #6).
    #[error("local storage error: {0}")]
    LocalIo(String),

    /// A protocol-shape problem: a malformed ticket address, an unparseable frame, an
    /// unsupported version — recognise-and-refuse, never a panic.
    #[error("{0}")]
    Protocol(String),

    /// The endpoint could not be built or bound.
    #[error("{0}")]
    Endpoint(String),

    /// Could not establish or use the QUIC connection to the peer.
    #[error("{0}")]
    Connection(String),

    /// The sender refused the request (DESIGN §4) — the message is the sender's reasoned text.
    #[error("refused by the sender: {0}")]
    Refused(String),

    /// The received bytes did not hash to the ticket's `sha256` — the partial was discarded
    /// (`sem_fileref_hash_verified_before_available`).
    #[error("received bytes do not match the ticket's sha256 — the partial download was discarded")]
    HashMismatch,

    /// The connection ended without the transfer completing, and it was NOT a peer-initiated
    /// cancel (DESIGN §4/§6) — a network drop, not an application close.
    #[error("{0}")]
    ConnectionLost(String),

    /// The peer explicitly cancelled (QUIC close, application error code 1 — DESIGN §4).
    #[error("cancelled by peer")]
    Cancelled,
}
