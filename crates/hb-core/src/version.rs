//! Schema & crypto version discriminants (spec §Schema & crypto versioning).
//!
//! Two values are frozen the moment events exist in the wild, so both are fixed here
//! and carried in signed content:
//!   - `SCHEMA_V` versions the Hoardbook *payload* schema (Nostr `kind` versions the envelope).
//!   - `CRYPTO_V` versions the browse-key → NIP-44 KDF and the share-code framing.
//!
//! Readers must *recognise* an unknown (future) version and refuse it cleanly, never
//! silently mis-parse — that is what makes the format forward-compatible.

use crate::error::HbError;

/// Hoardbook payload schema version, embedded in each signed event.
pub const SCHEMA_V: u8 = 1;

/// Crypto/KDF version for the browse-key derivation, the listing AAD, the binding token,
/// and the share-code framing. Bumping it is a deliberate flag-day.
pub const CRYPTO_V: u8 = 1;

/// Accept a parsed schema version, or surface an unknown one as a clean error.
/// A future client emitting `SCHEMA_V = 2` is *recognised* here (forward-compat), not
/// mis-decoded as v1.
pub fn check_schema(v: u8) -> Result<(), HbError> {
    if v == 0 || v > SCHEMA_V {
        Err(HbError::UnsupportedVersion(v))
    } else {
        Ok(())
    }
}

/// Accept a parsed crypto/KDF version, or surface an unknown one as a clean error.
pub fn check_crypto(v: u8) -> Result<(), HbError> {
    if v == 0 || v > CRYPTO_V {
        Err(HbError::UnsupportedVersion(v))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_schema_version_is_accepted() {
        assert!(check_schema(SCHEMA_V).is_ok());
        assert!(check_crypto(CRYPTO_V).is_ok());
    }

    #[test]
    fn unknown_schema_version_is_forward_compatible() {
        // A future, higher version is recognised and refused — not silently treated as v1.
        match check_schema(SCHEMA_V + 1) {
            Err(HbError::UnsupportedVersion(v)) => assert_eq!(v, SCHEMA_V + 1),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn zero_version_is_rejected() {
        assert!(matches!(check_schema(0), Err(HbError::UnsupportedVersion(0))));
        assert!(matches!(check_crypto(0), Err(HbError::UnsupportedVersion(0))));
    }
}
