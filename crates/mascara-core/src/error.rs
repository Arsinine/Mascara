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

    /// A folder manifest could not be decoded or its `root_hash` commitment did not verify
    /// (M3 brief §1; DESIGN §4 — the receiver buffers the whole manifest and checks
    /// `sha256(bytes) == folder_ref.root_hash` before trusting a single path). Every cause is
    /// reasoned: a decode failure, a schema-version mismatch, a cap violation, or a tampered
    /// byte-form — recognise-and-refuse, never a panic.
    #[error("manifest rejected: {0}")]
    Manifest(String),

    /// A hard-refuse content-check policy refused a transfer whose sniffed type did not match
    /// the declared name/mime (spec D7, M3 brief §1). Only emitted in hard-refuse mode; the
    /// default warn-and-acknowledge mode surfaces a `Mismatch` as a regular [`crate::content_check`]
    /// result, not an error.
    #[error("content check refused: {0}")]
    Content(String),

    /// The transfer-history store (`transfers/history.json`) could not be read, written, or
    /// updated. Local-only, purgeable (spec D9 / MAS-INV-2/6).
    #[error("transfer history error: {0}")]
    History(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("malformed keystore file: {0}")]
    Json(#[from] serde_json::Error),
}
