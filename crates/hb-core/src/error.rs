use thiserror::Error;

#[derive(Error, Debug)]
pub enum HbError {
    #[error("invalid Hoardbook ID: {0}")]
    InvalidId(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("message encryption failed")]
    EncryptionFailed,

    #[error("message decryption failed — wrong key or corrupted ciphertext")]
    DecryptionFailed,

    #[error("invalid encrypted message format")]
    InvalidEncryptedMessage,

    // --- v0.9 Nostr core (M1) ---
    #[error("nostr error: {0}")]
    Nostr(String),

    #[error("bech32 error: {0}")]
    Bech32(String),

    #[error("invalid share code: {0}")]
    InvalidShareCode(String),

    #[error("unsupported version byte: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("binding signed by unexpected identity")]
    WrongSigner,

    #[error("binding token expired")]
    BindingExpired,

    #[error("binding token not yet valid")]
    BindingNotYetValid,

    // --- v0.9 transfer auth (M4): the H2/H17 binding gate + resource caps ---
    /// The H17 follower gate denied the requester (their npub is not followed).
    /// The message intentionally carries "restricted to followers" — the wire-string
    /// the xfer server returns to an untrusted requester.
    #[error("this collection is restricted to followers only")]
    RestrictedToFollowers,

    /// An xfer request frame declared a length over the 64 KiB cap (AB7).
    #[error("request exceeds the maximum size of {max} bytes (declared {declared})")]
    RequestTooLarge { declared: usize, max: usize },

    /// A pre-auth binding-token frame declared a length over the cap (AB7 / Mission §5):
    /// rejected *before* any allocation so a hostile length-prefix can't drive a pre-auth OOM.
    #[error("token frame exceeds the maximum size of {max} bytes (declared {declared})")]
    TokenFrameTooLarge { declared: usize, max: usize },

    /// The per-npub concurrent download limit is reached (AB7).
    #[error("download limit reached — try again later")]
    DownloadLimitReached,

    // --- v1.0 portable backup crypto (M5): Argon2id → XChaCha20-Poly1305 ---
    /// The archive is not a Hoardbook backup (bad magic / too short / truncated header).
    #[error("not a Hoardbook backup archive: {0}")]
    InvalidBackup(String),

    /// The archive declares a `format_ver` this build does not speak. A v1 decoder speaks
    /// only v1 — a bumped/unknown version is a clean reject, never a misparse.
    #[error("unsupported backup format version: {0}")]
    UnsupportedBackupVersion(u8),

    /// An encrypted (`mode=1`) archive was handed to decrypt without a passphrase.
    #[error("this backup is passphrase-encrypted — a passphrase is required to restore it")]
    PassphraseRequired,

    /// The passphrase is below the minimum length (measured on the NFKC-normalized form).
    #[error("passphrase too short — use at least {min} characters")]
    PassphraseTooShort { min: usize },

    /// A KDF parameter in the (not-yet-authenticated) header is outside the accepted range.
    /// Rejected *before* Argon2id runs so a hostile archive can't OOM / thread-exhaust restore.
    #[error("backup KDF parameter out of range: {0}")]
    BackupParamsOutOfRange(String),
}
