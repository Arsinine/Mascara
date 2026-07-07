//! The in-memory session identity — the three keys of the v0.9 Nostr model.
//!
//! 1. the secp256k1 `Identity` (the irreplaceable `npub`; signs every event + DM),
//! 2. the bound Ed25519 **iroh transport key** (regenerable; the presence binding vouches for it),
//! 3. the account **browse-key** (the "club pass" carried in the `hbk` share code; seals the
//!    presence address and is the default collection key).
//!
//! Persisted as [`StoredIdentity`] (DPAPI-encrypted on Windows, 0600 file elsewhere). The UI
//! surfacing of the three keys + portable passphrase backup is M5.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hb_core::{BrowseKey, Identity, ShareCode};
use nostr::prelude::ToBech32;
use nostr::PublicKey;
use tokio::sync::RwLock;

use crate::store::StoredIdentity;

/// Schema version of the on-disk identity record.
pub const IDENTITY_VERSION: u8 = 1;

/// The loaded session identity (all three keys live in memory for the session).
pub struct AppIdentity {
    /// secp256k1 / `npub` — signs events + DMs.
    pub identity: Identity,
    /// Bound 32-byte Ed25519 iroh transport secret key.
    pub iroh_secret: [u8; 32],
    /// Account browse-key (the "club pass").
    pub browse_key: BrowseKey,
}

impl AppIdentity {
    /// Mint a fresh identity: a new npub, a fresh iroh transport key, a fresh account browse-key.
    pub fn generate() -> Self {
        Self {
            identity: Identity::generate(),
            iroh_secret: rand::random(),
            browse_key: rand::random(),
        }
    }

    /// Import an existing Nostr secret key (`nsec` or hex): the pasted key becomes the `npub`,
    /// and a **fresh** iroh transport key + account browse-key are minted (the other two keys are
    /// regenerable and need not — must not — be carried in from elsewhere). Distinct from the
    /// whole-directory restore path. A malformed key is a reasoned `Err`, never a panic.
    pub fn from_nsec(nsec: &str) -> Result<Self> {
        let identity = Identity::from_secret(nsec)
            .map_err(|e| anyhow!(e.to_string()))
            .context("parsing the imported Nostr secret key")?;
        Ok(Self { identity, iroh_secret: rand::random(), browse_key: rand::random() })
    }

    /// Reconstruct from the on-disk record.
    pub fn from_stored(s: &StoredIdentity) -> Result<Self> {
        let identity = Identity::from_secret(&s.nsec)
            .map_err(|e| anyhow!(e.to_string()))
            .context("parsing stored nsec")?;
        let iroh_secret: [u8; 32] = hex::decode(&s.iroh_secret_hex)
            .context("decoding iroh secret")?
            .try_into()
            .map_err(|_| anyhow!("iroh secret must be exactly 32 bytes"))?;
        let browse_key: [u8; 32] = hex::decode(&s.browse_key_hex)
            .context("decoding browse key")?
            .try_into()
            .map_err(|_| anyhow!("browse key must be exactly 32 bytes"))?;
        Ok(Self { identity, iroh_secret, browse_key })
    }

    /// Serialize to the on-disk record.
    pub fn to_stored(&self) -> Result<StoredIdentity> {
        let nsec = self
            .identity
            .keys()
            .secret_key()
            .to_bech32()
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok(StoredIdentity {
            version: IDENTITY_VERSION,
            nsec,
            iroh_secret_hex: hex::encode(self.iroh_secret),
            browse_key_hex: hex::encode(self.browse_key),
        })
    }

    /// The bech32 `npub` — the identity everywhere.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    /// The raw secp256k1 public key.
    pub fn public_key(&self) -> PublicKey {
        self.identity.public_key()
    }

    /// The bound iroh node key (32-byte Ed25519 public key), derived from the transport secret.
    pub fn iroh_node_key(&self) -> [u8; 32] {
        *iroh::SecretKey::from_bytes(&self.iroh_secret).public().as_bytes()
    }

    /// The full `hbk…` share code (npub + account browse-key) — the "club pass".
    pub fn share_code(&self) -> Result<String> {
        ShareCode::Full { pubkey: self.identity.public_key(), browse_key: self.browse_key }
            .encode()
            .map_err(|e| anyhow!(e.to_string()))
    }
}

/// Managed state: the loaded identity, or `None` before generate/import.
pub type SharedIdentity = Arc<RwLock<Option<AppIdentity>>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_roundtrip_through_stored() {
        let id = AppIdentity::generate();
        let npub = id.npub();
        let node_key = id.iroh_node_key();
        let browse = id.browse_key;

        let stored = id.to_stored().unwrap();
        let back = AppIdentity::from_stored(&stored).unwrap();

        assert_eq!(back.npub(), npub, "npub survives the storage roundtrip");
        assert_eq!(back.iroh_node_key(), node_key, "iroh node key survives");
        assert_eq!(back.browse_key, browse, "account browse-key survives");
    }

    #[test]
    fn share_code_is_full_hbk_carrying_browse_key() {
        let id = AppIdentity::generate();
        let code = id.share_code().unwrap();
        assert!(code.starts_with("hbk1"), "share code must be a full hbk code, got {code}");
        let parsed = ShareCode::parse(&code).unwrap();
        assert_eq!(parsed.pubkey(), id.public_key());
        assert_eq!(parsed.browse_key(), Some(id.browse_key));
    }

    #[test]
    fn distinct_identities_have_distinct_keys() {
        let a = AppIdentity::generate();
        let b = AppIdentity::generate();
        assert_ne!(a.npub(), b.npub());
        assert_ne!(a.iroh_node_key(), b.iroh_node_key());
        assert_ne!(a.browse_key, b.browse_key);
    }
}
