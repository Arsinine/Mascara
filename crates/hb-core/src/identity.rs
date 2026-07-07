//! Nostr-native identity: a secp256k1 / BIP-340 Schnorr keypair, its `npub` (NIP-19),
//! and NIP-01 event signing / verification (spec §Why Cryptographic Identity?, §The Key).
//!
//! This is the sole cryptographic identity. An Ed25519 key survives only as the bound iroh
//! transport key (see `binding`), never as identity.

use nostr::prelude::*;

use crate::error::HbError;

fn nostr_err(e: impl std::fmt::Display) -> HbError {
    HbError::Nostr(e.to_string())
}

/// A Hoardbook identity — the one irreplaceable secret.
#[derive(Clone)]
pub struct Identity {
    keys: Keys,
}

impl Identity {
    /// Mint a fresh identity.
    pub fn generate() -> Self {
        Self { keys: Keys::generate() }
    }

    /// Load an identity from a secret key, accepting hex or bech32 (`nsec…`).
    pub fn from_secret(secret: &str) -> Result<Self, HbError> {
        Ok(Self { keys: Keys::parse(secret).map_err(nostr_err)? })
    }

    /// The public key as a bech32 `npub` (NIP-19) — the identity everywhere.
    pub fn npub(&self) -> String {
        // A freshly built/parsed key always bech32-encodes; surfaced as a String for the UI.
        self.keys
            .public_key()
            .to_bech32()
            .expect("a valid secp256k1 public key always encodes to npub")
    }

    /// The raw secp256k1 public key.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Borrow the underlying signer (used by `event` / `binding` to sign).
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Sign a built event with this identity (offline; no relay).
    pub fn sign(&self, builder: EventBuilder) -> Result<Event, HbError> {
        builder.sign_with_keys(&self.keys).map_err(nostr_err)
    }
}

/// Decode a bech32 `npub` to a public key. The bech32 checksum rejects typos here,
/// before the key is ever used (replaces the old `hb1_` double-SHA256 checksum).
pub fn parse_npub(npub: &str) -> Result<PublicKey, HbError> {
    PublicKey::from_bech32(npub).map_err(|e| HbError::InvalidPublicKey(e.to_string()))
}

/// Verify a NIP-01 event: the Schnorr signature *and* the canonical id both check out.
/// A tampered event (mutated content/tags) fails the id check; a forged signature fails
/// the signature check.
pub fn verify_event(event: &Event) -> Result<(), HbError> {
    event.verify().map_err(|_| HbError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn npub_roundtrips_via_nip19() {
        let id = Identity::generate();
        let npub = id.npub();
        assert!(npub.starts_with("npub1"), "expected bech32 npub, got {npub}");
        // Decoding must recover the exact public key.
        assert_eq!(parse_npub(&npub).unwrap(), id.public_key());
    }

    #[test]
    fn mangled_npub_rejected() {
        let id = Identity::generate();
        let mut npub = id.npub();
        // Flip one character in the data part — the bech32 checksum must catch it.
        let last = npub.pop().unwrap();
        npub.push(if last == 'q' { 'p' } else { 'q' });
        assert!(matches!(parse_npub(&npub), Err(HbError::InvalidPublicKey(_))));
    }

    #[test]
    fn event_signs_and_verifies() {
        let id = Identity::generate();
        let event = id.sign(EventBuilder::new(Kind::TextNote, "hoardbook")).unwrap();
        assert_eq!(event.pubkey, id.public_key());
        assert!(verify_event(&event).is_ok());
    }

    #[test]
    fn tampered_event_rejected() {
        // ID1: an event mutated after signing fails verification (id no longer matches).
        let id = Identity::generate();
        let mut event = id.sign(EventBuilder::new(Kind::TextNote, "original")).unwrap();
        event.content = "tampered".to_string();
        assert!(matches!(verify_event(&event), Err(HbError::InvalidSignature)));
    }

    #[test]
    fn wrong_key_rejected() {
        // An event whose stored pubkey is swapped for another identity's fails verification.
        let a = Identity::generate();
        let b = Identity::generate();
        let mut event = a.sign(EventBuilder::new(Kind::TextNote, "x")).unwrap();
        event.pubkey = b.public_key();
        assert!(verify_event(&event).is_err());
    }

    #[test]
    fn from_secret_is_deterministic() {
        let id = Identity::generate();
        let nsec = id.keys().secret_key().to_bech32().unwrap();
        let reloaded = Identity::from_secret(&nsec).unwrap();
        assert_eq!(reloaded.public_key(), id.public_key());
    }

    #[test]
    fn nip01_id_matches_known_vector() {
        // Interop: the NIP-01 event id is SHA-256 of the canonical array
        // [0, pubkey_hex, created_at, kind, tags, content]. We compute it *independently*
        // (serde_json + sha2) and assert the `nostr` crate agrees — so our events carry the
        // same ids any other Nostr implementation would compute (the basis of interop).
        let id = Identity::generate();
        let created_at = 1_700_000_000u64;
        let kind = 1u16;
        let content = "hoardbook";
        let event = EventBuilder::new(Kind::from_u16(kind), content)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(id.keys())
            .unwrap();

        let pubkey_hex = id.public_key().to_hex();
        let canonical = serde_json::to_string(&serde_json::json!([
            0, pubkey_hex, created_at, kind, [], content
        ]))
        .unwrap();
        let expected = hex::encode(Sha256::digest(canonical.as_bytes()));

        assert_eq!(event.id.to_hex(), expected, "NIP-01 id must match the canonical SHA-256");
    }

    #[test]
    fn nip01_id_matches_known_vector_with_tags() {
        // Same interop check, now with tags present, so the tag serialization is covered too
        // (NIP-01 canonical form: [0, pubkey, created_at, kind, [["t","anime"],…], content]).
        let id = Identity::generate();
        let created_at = 1_700_000_000u64;
        let kind = 30_117u16;
        let content = "teaser";
        let event = EventBuilder::new(Kind::from_u16(kind), content)
            .tags([Tag::hashtag("anime"), Tag::identifier("hoardbook-teaser")])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(id.keys())
            .unwrap();

        let pubkey_hex = id.public_key().to_hex();
        let canonical = serde_json::to_string(&serde_json::json!([
            0, pubkey_hex, created_at, kind, [["t", "anime"], ["d", "hoardbook-teaser"]], content
        ]))
        .unwrap();
        let expected = hex::encode(Sha256::digest(canonical.as_bytes()));

        assert_eq!(event.id.to_hex(), expected, "tagged NIP-01 id must match canonical SHA-256");
    }
}
