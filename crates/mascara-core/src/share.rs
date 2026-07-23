//! The Hoardbook → Mascara seam: `ShareDescriptor` (MR-22, DOMAIN_MODEL "The seam").
//!
//! At ticket-creation Hoardbook emits a **share descriptor** — the catalog facts it already holds
//! for the chosen file (`name`, `size`, `sha256`, `md5`, `mime`, optional `link_assertion`) —
//! *statelessly* (no transfer record, no auto-launch — MAS-INV-5). Mascara **consumes** it and mints
//! a ticket from the carried facts; it **never computes** the content commitment (MR-13;
//! SEMANTIC_MODEL `sem_mascara_no_commitment_hashing` / `sem_ticket_built_from_descriptor`).
//!
//! **JSON, hex-encoded hashes.** A descriptor deserializes from JSON with `sha256`/`md5` as lowercase
//! hex strings (mirroring [`crate::ticket::Nonce`]'s hex serde), so a descriptor is human-inspectable
//! and hand-makeable for dev/testing while Hoardbook — the real minter — does not yet exist.
//!
//! **File-only at M1.** Folder descriptors (`root_hash`, streamed manifest) are M3; this seam carries
//! a single file's facts.

use serde::{Deserialize, Serialize};

use crate::assertion::LinkAssertion;
use crate::error::CoreError;
use crate::ticket::{Endpoint, FileRef, Nonce, Ticket};

/// The one-way seam artifact Mascara consumes (MR-22). The recipient's card never crosses this seam
/// (it is out-of-band from the recipient); this describes only the file being offered.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ShareDescriptor {
    pub name: String,
    pub size: u64,
    /// Content commitment, Hoardbook-precomputed (MR-13). Lowercase hex in JSON.
    #[serde(with = "hex_bytes")]
    pub sha256: [u8; 32],
    /// Advisory legacy-catalog interop hash (MR-11). Lowercase hex in JSON.
    #[serde(with = "hex_bytes")]
    pub md5: [u8; 16],
    pub mime: Option<String>,
    /// The optional per-transfer proof Hoardbook mints (verify-only in Mascara — [`LinkAssertion`]).
    pub link_assertion: Option<LinkAssertion>,
}

impl ShareDescriptor {
    /// Parse a descriptor from its JSON form. Any malformed input is a reasoned refusal.
    pub fn from_json_str(s: &str) -> Result<Self, CoreError> {
        serde_json::from_str(s)
            .map_err(|e| CoreError::Ticket(format!("malformed share descriptor: {e}")))
    }

    /// Load and parse a descriptor from a JSON file (the CLI's `mascara send <descriptor>`).
    pub fn from_json_file(path: &std::path::Path) -> Result<Self, CoreError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            CoreError::Ticket(format!("could not read share descriptor {}: {e}", path.display()))
        })?;
        Self::from_json_str(&raw)
    }

    /// Build a [`FileRef`] from the **carried** facts — NO hashing (MR-13). The commitment is
    /// Hoardbook's; Mascara only forwards it into the ticket.
    pub fn file_ref(&self) -> FileRef {
        FileRef {
            name: self.name.clone(),
            size: self.size,
            sha256: self.sha256,
            md5: self.md5,
            mime: self.mime.clone(),
        }
    }

    /// Mint a **file, download** ticket from this descriptor, carrying its `link_assertion`. The
    /// endpoint/key/expiry/nonce come from the caller (net at M2, synthetic in tests).
    pub fn into_file_ticket(
        self,
        endpoint: Endpoint,
        endpoint_key: [u8; 32],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        nonce: Nonce,
    ) -> Ticket {
        let file_ref = self.file_ref();
        Ticket::new_file(file_ref, endpoint, endpoint_key, self.link_assertion, expires_at, nonce)
    }
}

/// serde adapter: a fixed-width byte array as a lowercase-hex string in JSON (mirrors `Nonce`'s hex
/// serde). One generic module serves both the 32-byte sha256 and the 16-byte md5 fields.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<const N: usize, S: Serializer>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, const N: usize, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
        bytes.as_slice().try_into().map_err(|_| {
            serde::de::Error::custom(format!("expected {N} bytes of hex, got {}", bytes.len()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> String {
        // sha256 = 32 × 0x07, md5 = 16 × 0x11 — hand-written hex, the dev/testing path.
        format!(
            r#"{{
                "name": "Akira_1988.mkv",
                "size": 4096,
                "sha256": "{}",
                "md5": "{}",
                "mime": "video/x-matroska",
                "link_assertion": null
            }}"#,
            hex::encode([0x07u8; 32]),
            hex::encode([0x11u8; 16]),
        )
    }

    #[test]
    fn descriptor_round_trips_through_json_with_hex_hashes() {
        let d = ShareDescriptor::from_json_str(&sample_json()).unwrap();
        assert_eq!(d.name, "Akira_1988.mkv");
        assert_eq!(d.size, 4096);
        assert_eq!(d.sha256, [0x07u8; 32]);
        assert_eq!(d.md5, [0x11u8; 16]);
        assert_eq!(d.mime.as_deref(), Some("video/x-matroska"));
        // Re-serialize and re-parse: hashes stay hex, the descriptor is stable.
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains(&hex::encode([0x07u8; 32])), "sha256 must serialize as hex: {json}");
        assert_eq!(ShareDescriptor::from_json_str(&json).unwrap(), d);
    }

    #[test]
    fn file_ref_carries_the_hashes_without_computing() {
        let d = ShareDescriptor::from_json_str(&sample_json()).unwrap();
        let fr = d.file_ref();
        assert_eq!(fr.sha256, d.sha256, "sha256 is carried, not recomputed");
        assert_eq!(fr.md5, d.md5, "md5 is carried, not recomputed");
        assert_eq!(fr.name, d.name);
        assert_eq!(fr.size, d.size);
    }

    #[test]
    fn into_file_ticket_uses_carried_facts() {
        let d = ShareDescriptor::from_json_str(&sample_json()).unwrap();
        let sha = d.sha256;
        let ticket = d.into_file_ticket(Endpoint::default(), [3u8; 32], None, Nonce::mint());
        assert_eq!(ticket.file_ref.sha256, sha);
        assert_eq!(ticket.file_ref.md5, [0x11u8; 16]);
    }

    #[test]
    fn malformed_json_is_reasoned_not_a_panic() {
        assert!(matches!(ShareDescriptor::from_json_str("not json"), Err(CoreError::Ticket(_))));
        // Wrong-length sha256 hex is refused too.
        let bad = sample_json().replace(&hex::encode([0x07u8; 32]), "0011");
        assert!(matches!(ShareDescriptor::from_json_str(&bad), Err(CoreError::Ticket(_))));
    }
}
