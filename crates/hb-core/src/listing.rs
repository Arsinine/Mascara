//! Collection-listing encryption — NIP-44 v2 under a *symmetric* browse-key
//! (spec §The Collection, §Data Model).
//!
//! NIP-44's headline API is ECDH between two secp256k1 keys, but the browse-key is a shared
//! 32-byte symmetric secret. `nostr`'s `nip44::v2::ConversationKey::new([u8; 32])` accepts a
//! raw conversation key, which we derive from the browse-key through a **versioned HKDF** —
//! the crypto-version byte is the HKDF `info`, so each version is a domain-separated key. The
//! version is carried in the listing event's **signed tag** and checked on decrypt, so an
//! unknown version is *recognised and refused*, never mis-decrypted. The ciphertext is
//! **base64** (the NIP-44 standard content encoding), ready to drop into a Nostr event.

use base64::Engine as _;
use hkdf::Hkdf;
use nostr::nips::nip44::v2::{decrypt_to_bytes, encrypt_to_bytes, ConversationKey};
use sha2::Sha256;

use crate::error::HbError;
use crate::version::{check_crypto, CRYPTO_V};

/// A 32-byte symmetric browse-key.
pub type BrowseKey = [u8; 32];

const HKDF_SALT: &[u8] = b"hoardbook/browse-key";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Derive the NIP-44 conversation key from the browse-key for a given crypto version.
/// The HKDF `info` is a labelled, version-bearing context string (RFC 5869 domain
/// separation, matching the labelled convention in `crypto.rs`), so each crypto version
/// derives an independent key.
fn conversation_key(browse_key: &BrowseKey, crypto_v: u8) -> ConversationKey {
    let mut info = b"hoardbook/browse-key/v".to_vec();
    info.push(crypto_v);
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), browse_key);
    let mut ck = [0u8; 32];
    hk.expand(&info, &mut ck)
        .expect("32 is a valid HKDF-SHA256 output length");
    ConversationKey::new(ck)
}

/// Encrypt a listing under the browse-key at the current crypto version. Returns the base64
/// content for the listing event; the caller records [`CRYPTO_V`] in the event's signed tag.
pub fn encrypt_listing(browse_key: &BrowseKey, listing_json: &str) -> Result<String, HbError> {
    let ck = conversation_key(browse_key, CRYPTO_V);
    let bytes =
        encrypt_to_bytes(&ck, listing_json.as_bytes()).map_err(|e| HbError::Nostr(e.to_string()))?;
    Ok(B64.encode(bytes))
}

/// Decrypt a listing. `crypto_v` is the version read from the listing event's signed tag; an
/// unknown version is refused before any decryption is attempted.
pub fn decrypt_listing(
    browse_key: &BrowseKey,
    crypto_v: u8,
    content_b64: &str,
) -> Result<String, HbError> {
    check_crypto(crypto_v)?;
    let ck = conversation_key(browse_key, crypto_v);
    let bytes = B64
        .decode(content_b64.as_bytes())
        .map_err(|_| HbError::InvalidEncryptedMessage)?;
    let plain = decrypt_to_bytes(&ck, &bytes).map_err(|_| HbError::DecryptionFailed)?;
    String::from_utf8(plain).map_err(|_| HbError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str =
        r#"{"slug":"criterion","content_types":["video"],"items":[{"name":"Seven Samurai"}]}"#;

    #[test]
    fn browse_key_roundtrip() {
        let bk: BrowseKey = rand::random();
        let ct = encrypt_listing(&bk, LISTING).unwrap();
        assert_eq!(decrypt_listing(&bk, CRYPTO_V, &ct).unwrap(), LISTING);
    }

    #[test]
    fn content_is_base64_nip44_not_hex() {
        let bk: BrowseKey = rand::random();
        let ct = encrypt_listing(&bk, LISTING).unwrap();
        // Valid base64 whose bytes are a NIP-44 v2 payload (version byte 0x02 first).
        let raw = B64.decode(ct.as_bytes()).expect("content must be base64");
        assert_eq!(raw[0], 2, "NIP-44 v2 payload begins with version byte 2");
    }

    #[test]
    fn ciphertext_nonempty_and_ne_plaintext() {
        let bk: BrowseKey = rand::random();
        let ct = encrypt_listing(&bk, LISTING).unwrap();
        assert!(!ct.is_empty());
        assert_ne!(ct, LISTING);
    }

    #[test]
    fn wrong_browse_key_fails_cleanly() {
        let a: BrowseKey = rand::random();
        let b: BrowseKey = rand::random();
        let ct = encrypt_listing(&a, LISTING).unwrap();
        assert!(matches!(decrypt_listing(&b, CRYPTO_V, &ct), Err(HbError::DecryptionFailed)));
    }

    #[test]
    fn nonce_is_unique_per_encryption() {
        let bk: BrowseKey = rand::random();
        let a = encrypt_listing(&bk, LISTING).unwrap();
        let b = encrypt_listing(&bk, LISTING).unwrap();
        assert_ne!(a, b, "NIP-44 uses a random nonce; identical ciphertext would be a red flag");
    }

    #[test]
    fn unknown_kdf_version_is_recognised_not_misdecrypted() {
        // A signed tag claiming a future crypto version is refused cleanly, not decrypted
        // under a wrong key (which would surface as a confusing MAC failure).
        let bk: BrowseKey = rand::random();
        let ct = encrypt_listing(&bk, LISTING).unwrap();
        assert!(matches!(
            decrypt_listing(&bk, CRYPTO_V + 1, &ct),
            Err(HbError::UnsupportedVersion(v)) if v == CRYPTO_V + 1
        ));
    }

    #[test]
    fn kdf_versions_are_domain_separated() {
        // The forward-compat seam: a future version derives a different conversation key, so
        // v1 ciphertext would not decrypt under a v2 key (tested at the helper level since the
        // public API only admits the current version today).
        let bk: BrowseKey = rand::random();
        let v1 = conversation_key(&bk, 1);
        let v2 = conversation_key(&bk, 2);
        let ct = encrypt_to_bytes(&v1, b"listing").unwrap();
        assert!(decrypt_to_bytes(&v2, &ct).is_err(), "a KDF version bump must domain-separate");
        assert_eq!(decrypt_to_bytes(&v1, &ct).unwrap(), b"listing");
    }
}
