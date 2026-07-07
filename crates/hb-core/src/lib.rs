#![forbid(unsafe_code)]

// --- Shared domain types (collections / profiles) consumed across crates. ---
pub mod error;
pub mod types;

// --- v0.9 Nostr core: secp256k1 identity, NIP-01 events, NIP-44 listings,
//     the npub→iroh binding + xfer gate, the hbk share code. (The legacy Ed25519
//     identity / JCS / signed-envelope core was removed with its hb-app consumer in M4.) ---
pub mod backup;
pub mod binding;
pub mod event;
pub mod fingerprint;
pub mod gate;
pub mod identity;
pub mod listing;
pub mod sharecode;
mod tag_util;
pub mod version;

pub use error::HbError;
pub use types::{Collection, DirectoryItem, ItemType, Profile, SocialLink};

pub use backup::{
    decrypt_backup, encrypt_backup, is_encrypted_backup, BackupMode, BACKUP_FORMAT_VER,
    MIN_PASSPHRASE_LEN,
};
pub use binding::{
    build_binding, resolve_node_key, seal_addrs, unseal_addrs, verify_binding, Binding, SealedAddr,
};
pub use fingerprint::{fingerprint, Fingerprint};
pub use gate::{
    build_binding_token, check_download_limit, check_request_len, check_token_frame_len,
    follower_gate, verify_binding_token, Token, MAX_TOKEN_FRAME_BYTES, MAX_XFER_REQUEST_BYTES,
};
pub use identity::Identity;
pub use listing::{decrypt_listing, encrypt_listing, BrowseKey};
pub use sharecode::ShareCode;
pub use version::SCHEMA_V;
