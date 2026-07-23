//! Crate error type. One enum, reasoned variants — callers (CLI/GUI) surface these verbatim, so
//! messages are written for humans.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid contact card: {0}")]
    InvalidCard(String),

    #[error("no Mascara identity found at {0} — run init first")]
    NoIdentity(String),

    #[error("keystore error: {0}")]
    Keystore(String),

    /// A ticket could not be sealed to the recipient (encoding or sealed-box encryption failure).
    #[error("could not seal ticket: {0}")]
    Seal(String),

    /// A ticket string/file could not be opened into a `Ticket`. Every cause is reasoned — a wrong
    /// sealing key, tampered bytes, a missing/foreign prefix, and an unknown schema version are all
    /// recognise-and-refuse, never a panic (spec MT5 / M1 brief §1).
    #[error("could not open ticket: {0}")]
    Ticket(String),

    /// The issued-ticket registry (`tickets/issued.json`) could not be read, written, or updated.
    #[error("ticket registry error: {0}")]
    Registry(String),

    /// A `link_assertion` failed verification — a forged signature, the wrong card, the wrong
    /// nonce, or an npub that is not a valid x-only key (spec MT3 / M1 brief §1).
    #[error("link assertion rejected: {0}")]
    Assertion(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("malformed keystore file: {0}")]
    Json(#[from] serde_json::Error),
}
