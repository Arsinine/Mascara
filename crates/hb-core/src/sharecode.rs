//! The share code — the "secret-club pass" (spec §The Key).
//!
//! Two forms, by blast radius:
//!   - a **bare `npub`** (NIP-19) → follow + public teaser only (no browse-key);
//!   - a full **`hbk…`** code → follow + decrypt listings.
//!
//! Wire format of the full code is bech32 with HRP **`hbk`** (so the rendered string
//! begins `hbk1…`, since `1` is the bech32 separator) over
//! `version[1] ‖ pubkey[32] ‖ browse_key[32]`. The leading **version byte** keeps this
//! frozen-at-launch, copy-pasted credential from being format-less (spec demands a version
//! discriminant on everything that persists in the wild; this was an audit finding).

use bech32::{Bech32, Hrp};
use nostr::prelude::*;

use crate::error::HbError;
use crate::version::CRYPTO_V;

/// bech32 HRP for a full share code. NB: the *prefix* is `hbk`; the rendered string is `hbk1…`.
const HRP_STR: &str = "hbk";
/// Version byte carried at the head of the `hbk` payload. Tied to the crypto version.
pub const SHARECODE_VERSION: u8 = CRYPTO_V;

/// A parsed share code.
#[derive(Clone)]
pub enum ShareCode {
    /// Bare `npub`: the holder can follow and see the public teaser, but not the listings.
    FollowOnly { pubkey: PublicKey },
    /// Full code: the holder can also decrypt the owner's collection listings.
    Full { pubkey: PublicKey, browse_key: [u8; 32] },
}

impl ShareCode {
    /// The peer's identity, present in either form.
    pub fn pubkey(&self) -> PublicKey {
        match self {
            ShareCode::FollowOnly { pubkey } | ShareCode::Full { pubkey, .. } => *pubkey,
        }
    }

    /// The browse-key, if this is a full code.
    pub fn browse_key(&self) -> Option<[u8; 32]> {
        match self {
            ShareCode::Full { browse_key, .. } => Some(*browse_key),
            ShareCode::FollowOnly { .. } => None,
        }
    }

    /// Render to a string: `FollowOnly → npub1…`, `Full → hbk1…`.
    pub fn encode(&self) -> Result<String, HbError> {
        match self {
            ShareCode::FollowOnly { pubkey } => {
                pubkey.to_bech32().map_err(|e| HbError::Bech32(e.to_string()))
            }
            ShareCode::Full { pubkey, browse_key } => {
                let mut data = Vec::with_capacity(65);
                data.push(SHARECODE_VERSION);
                data.extend_from_slice(&pubkey.to_bytes());
                data.extend_from_slice(browse_key);
                let hrp = Hrp::parse(HRP_STR).map_err(|e| HbError::Bech32(e.to_string()))?;
                bech32::encode::<Bech32>(hrp, &data).map_err(|e| HbError::Bech32(e.to_string()))
            }
        }
    }

    /// Parse a pasted string. `npub1…` → follow-only; `hbk1…` → full (version-checked).
    /// Garbage, wrong HRP, wrong length, or an unknown version all return a clean `Err`.
    pub fn parse(s: &str) -> Result<Self, HbError> {
        let s = s.trim();

        if s.starts_with("npub1") {
            let pubkey =
                PublicKey::from_bech32(s).map_err(|e| HbError::InvalidShareCode(e.to_string()))?;
            return Ok(ShareCode::FollowOnly { pubkey });
        }

        let (hrp, data) = bech32::decode(s).map_err(|e| HbError::Bech32(e.to_string()))?;
        if hrp.as_str() != HRP_STR {
            return Err(HbError::InvalidShareCode(format!("unexpected hrp '{}'", hrp.as_str())));
        }
        if data.len() != 65 {
            return Err(HbError::InvalidShareCode(format!(
                "expected 65 payload bytes, got {}",
                data.len()
            )));
        }
        let version = data[0];
        if version != SHARECODE_VERSION {
            return Err(HbError::UnsupportedVersion(version));
        }
        let pubkey = PublicKey::from_slice(&data[1..33])
            .map_err(|e| HbError::InvalidShareCode(e.to_string()))?;
        let mut browse_key = [0u8; 32];
        browse_key.copy_from_slice(&data[33..65]);
        Ok(ShareCode::Full { pubkey, browse_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn full() -> ([u8; 32], ShareCode) {
        let pubkey = Identity::generate().public_key();
        let browse_key: [u8; 32] = rand::random();
        (browse_key, ShareCode::Full { pubkey, browse_key })
    }

    #[test]
    fn hbk_sharecode_roundtrips() {
        let (browse_key, sc) = full();
        let s = sc.encode().unwrap();
        assert!(s.starts_with("hbk1"), "full code must render hbk1…, got {s}");
        let back = ShareCode::parse(&s).unwrap();
        assert_eq!(back.pubkey(), sc.pubkey());
        assert_eq!(back.browse_key(), Some(browse_key));
    }

    #[test]
    fn sharecode_carries_version_byte() {
        let (_bk, sc) = full();
        let (_hrp, data) = bech32::decode(&sc.encode().unwrap()).unwrap();
        assert_eq!(data[0], SHARECODE_VERSION, "first payload byte is the version");
        assert_eq!(data.len(), 65);
    }

    #[test]
    fn unknown_sharecode_version_rejected() {
        // Forge an hbk string whose version byte is a future version → recognised, refused.
        let pubkey = Identity::generate().public_key();
        let mut data = Vec::with_capacity(65);
        data.push(SHARECODE_VERSION + 1);
        data.extend_from_slice(&pubkey.to_bytes());
        data.extend_from_slice(&[7u8; 32]);
        let hrp = Hrp::parse(HRP_STR).unwrap();
        let forged = bech32::encode::<Bech32>(hrp, &data).unwrap();
        assert!(matches!(ShareCode::parse(&forged), Err(HbError::UnsupportedVersion(v)) if v == SHARECODE_VERSION + 1));
    }

    #[test]
    fn bare_npub_parses_as_follow_only() {
        let id = Identity::generate();
        let sc = ShareCode::parse(&id.npub()).unwrap();
        assert!(matches!(sc, ShareCode::FollowOnly { .. }));
        assert_eq!(sc.pubkey(), id.public_key());
        assert_eq!(sc.browse_key(), None);
    }

    #[test]
    fn mangled_checksum_rejected() {
        // ID2: a single-character corruption is caught by the bech32 checksum before use.
        let (_bk, sc) = full();
        let mut s = sc.encode().unwrap();
        let last = s.pop().unwrap();
        s.push(if last == 'q' { 'p' } else { 'q' });
        assert!(ShareCode::parse(&s).is_err());
    }

    #[test]
    fn wrong_hrp_rejected() {
        // A well-formed bech32 string under a different HRP is not a share code.
        let hrp = Hrp::parse("xyz").unwrap();
        let s = bech32::encode::<Bech32>(hrp, &[0u8; 65]).unwrap();
        assert!(matches!(ShareCode::parse(&s), Err(HbError::InvalidShareCode(_))));
    }

    #[test]
    fn truncated_input_rejected() {
        // Right HRP, wrong byte count.
        let hrp = Hrp::parse(HRP_STR).unwrap();
        let s = bech32::encode::<Bech32>(hrp, &[SHARECODE_VERSION; 10]).unwrap();
        assert!(matches!(ShareCode::parse(&s), Err(HbError::InvalidShareCode(_))));
    }

    #[test]
    fn garbage_never_panics() {
        // Fuzz: arbitrary inputs must always return Err, never panic.
        for s in ["", "hbk1", "npub1", "hbk1zzzzz", "not a code", "::::", "hbk1qqqqqqqqqq"] {
            assert!(ShareCode::parse(s).is_err(), "{s:?} should be Err");
        }
        for i in 0u16..512 {
            let junk: String = (0..i % 120).map(|j| (b'a' + ((i + j) % 26) as u8) as char).collect();
            let _ = ShareCode::parse(&junk); // must not panic
        }
    }
}
