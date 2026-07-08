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

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("malformed keystore file: {0}")]
    Json(#[from] serde_json::Error),
}
