//! The Hoardbook → Mascara seam: `ShareDescriptor` (MR-22, DOMAIN_MODEL "The seam").
//!
//! At ticket-creation Hoardbook emits a **share descriptor** — the catalog facts it already holds
//! for the chosen file or folder — *statelessly* (no transfer record, no auto-launch — MAS-INV-5).
//! Mascara **consumes** it and mints a ticket from the carried facts; it **never computes** the
//! content commitment (MR-13; SEMANTIC_MODEL `sem_mascara_no_commitment_hashing` /
//! `sem_ticket_built_from_descriptor`).
//!
//! **JSON, hex-encoded hashes.** A descriptor deserializes from JSON with `sha256`/`md5`/`root_hash`
//! as lowercase hex strings (mirroring [`crate::ticket::Nonce`]'s hex serde), so a descriptor is
//! human-inspectable and hand-makeable for dev/testing while Hoardbook — the real minter — does not
//! yet exist.
//!
//! **v2 (M3): `kind`-tagged JSON enum.** A descriptor is `"kind": "file"` or `"kind": "folder"`.
//! The file form carries one file's facts; the folder form carries the manifest entries plus the
//! claimed `root_hash`. Mascara encodes the folder entries via [`crate::manifest::encode`] and
//! **verifies `sha256(bytes) == the descriptor's claimed root_hash`** before minting — this is
//! consistency-checking Hoardbook's OWN claim (the manifest bytes hash to what the descriptor
//! asserts), not Mascara originating a commitment (the per-file sha256/md5 stay carried, never
//! computed — MR-13).

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::assertion::LinkAssertion;
use crate::error::CoreError;
use crate::manifest::{self, Manifest, ManifestEntry};
use crate::ticket::{Endpoint, FileRef, FolderRef, Nonce, Ticket};

/// The JSON-facing form of one manifest entry inside a folder descriptor: identical fields to
/// [`ManifestEntry`] but with the hashes as lowercase-hex strings (the same hex-adapter pattern
/// the file descriptor's `sha256`/`md5` use). This is the **transport** form across the Hoardbook
/// seam; it converts to the in-memory [`ManifestEntry`] (raw byte arrays, the form the manifest's
/// postcard byte-layout freezes) via [`FolderEntry::into_manifest_entry`]. The in-memory type is
/// reused, not duplicated — this adapter only carries the JSON-side hash encoding.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FolderEntry {
    pub rel_path: String,
    pub size: u64,
    #[serde(with = "hex_bytes")]
    pub sha256: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub md5: [u8; 16],
    pub mode: u32,
}

impl FolderEntry {
    /// Convert the JSON-facing hex-hash form to the in-memory manifest entry (raw byte arrays).
    pub fn into_manifest_entry(self) -> ManifestEntry {
        ManifestEntry {
            rel_path: self.rel_path,
            size: self.size,
            sha256: self.sha256,
            md5: self.md5,
            mode: self.mode,
        }
    }
}

impl From<&ManifestEntry> for FolderEntry {
    fn from(e: &ManifestEntry) -> Self {
        FolderEntry {
            rel_path: e.rel_path.clone(),
            size: e.size,
            sha256: e.sha256,
            md5: e.md5,
            mode: e.mode,
        }
    }
}

/// The one-way seam artifact Mascara consumes (MR-22). The recipient's card never crosses this seam
/// (it is out-of-band from the recipient); this describes only the file or folder being offered.
///
/// `kind`-tagged JSON enum (`#[serde(tag = "kind", rename_all = "lowercase")]`): the `"kind"` field
/// selects the variant and the variant's fields sit alongside it. The seam format is private
/// (Hoardbook doesn't exist yet), so a clean break from the M1 flat-struct shape is correct.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ShareDescriptor {
    File(FileDescriptor),
    Folder(FolderDescriptor),
}

/// One file's facts (the M1 shape, now behind `"kind": "file"`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FileDescriptor {
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

/// A folder's facts: a name, the claimed `root_hash` of its manifest, and the entries. Mascara
/// **re-encodes the entries and checks `sha256(bytes) == root_hash`** at ticket-creation — a
/// consistency check on Hoardbook's own two claims (entries vs root_hash), never an origin
/// commitment (MR-13: per-entry sha256/md5 are carried, not computed here).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FolderDescriptor {
    pub name: String,
    /// The folder commitment `sha256(manifest bytes)` Hoardbook precomputed (MR-13). Lowercase hex
    /// in JSON. Verified against the entries below before a folder ticket is minted.
    #[serde(with = "hex_bytes")]
    pub root_hash: [u8; 32],
    /// The manifest entries in their JSON-facing hex-hash form ([`FolderEntry`]); converted to the
    /// in-memory [`ManifestEntry`] (raw byte arrays) at mint time for the manifest postcard
    /// byte-form the `root_hash` commits to.
    pub entries: Vec<FolderEntry>,
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
}

impl FileDescriptor {
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
    /// endpoint/card/expiry/nonce come from the caller (net at M2, synthetic in tests).
    pub fn into_file_ticket(
        self,
        endpoint: Endpoint,
        sender_card: Vec<u8>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        nonce: Nonce,
    ) -> Ticket {
        let file_ref = self.file_ref();
        Ticket::new_file(file_ref, endpoint, sender_card, self.link_assertion, expires_at, nonce)
    }
}

impl FolderDescriptor {
    /// Encode the entries to their deterministic manifest byte-form, **verify
    /// `sha256(bytes) == self.root_hash`**, and on success return the manifest bytes + the
    /// [`FolderRef`]. A mismatch is a reasoned refusal (the descriptor's own two claims disagree —
    /// consistency-checking Hoardbook, not originating a commitment, MR-13).
    ///
    /// Returns the manifest bytes too so the caller (the CLI) can store them for serving later in
    /// M3; `root_hash` is the commitment a receiver will re-verify against its own fetched copy.
    pub fn verify_root_hash(&self) -> Result<(Vec<u8>, FolderRef), CoreError> {
        let entries: Vec<ManifestEntry> = self.entries.iter().map(|e| e.clone().into_manifest_entry()).collect();
        let manifest = Manifest { v: manifest::MANIFEST_VERSION, entries };
        let bytes = manifest::encode(&manifest)?;
        let actual: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        if actual != self.root_hash {
            return Err(CoreError::Ticket(format!(
                "folder descriptor's root_hash {} does not match sha256 of its own entries {} — \
                 Hoardbook's two claims disagree; refusing to mint a ticket from an inconsistent \
                 descriptor",
                hex::encode(self.root_hash),
                hex::encode(actual),
            )));
        }
        let folder_ref = FolderRef { name: self.name.clone(), root_hash: self.root_hash };
        Ok((bytes, folder_ref))
    }

    /// Mint a **folder, download** ticket from this descriptor: verify the root_hash against the
    /// entries first ([`Self::verify_root_hash`]), then carry the `FolderRef`. Returns the ticket
    /// and the manifest bytes (the caller serves them at a later M3 stage).
    pub fn into_folder_ticket(
        self,
        endpoint: Endpoint,
        sender_card: Vec<u8>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        nonce: Nonce,
    ) -> Result<(Ticket, Vec<u8>), CoreError> {
        let (manifest_bytes, folder_ref) = self.verify_root_hash()?;
        let ticket = Ticket::new_folder(
            folder_ref,
            endpoint,
            sender_card,
            self.link_assertion,
            expires_at,
            nonce,
        );
        Ok((ticket, manifest_bytes))
    }
}

/// serde adapter: a fixed-width byte array as a lowercase-hex string in JSON (mirrors `Nonce`'s hex
/// serde). One generic module serves the 32-byte sha256/root_hash and the 16-byte md5 fields.
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

    fn sample_file_json() -> String {
        // sha256 = 32 × 0x07, md5 = 16 × 0x11 — hand-written hex, the dev/testing path.
        format!(
            r#"{{
                "kind": "file",
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

    fn sample_folder_json(root_hash_hex: &str) -> String {
        // Two entries; the root_hash is supplied by the caller so a mismatch case can be built.
        format!(
            r#"{{
                "kind": "folder",
                "name": "subs",
                "root_hash": "{root_hash_hex}",
                "entries": [
                    {{
                        "rel_path": "Akira_1988.mkv",
                        "size": 4096,
                        "sha256": "{}",
                        "md5": "{}",
                        "mode": 420
                    }},
                    {{
                        "rel_path": "subs/en.srt",
                        "size": 128,
                        "sha256": "{}",
                        "md5": "{}",
                        "mode": 384
                    }}
                ],
                "link_assertion": null
            }}"#,
            hex::encode([0x07u8; 32]),
            hex::encode([0x11u8; 16]),
            hex::encode([0x22u8; 32]),
            hex::encode([0x33u8; 16]),
        )
    }

    #[test]
    fn file_descriptor_round_trips_through_json_with_hex_hashes() {
        let d = ShareDescriptor::from_json_str(&sample_file_json()).unwrap();
        let ShareDescriptor::File(file) = d else { panic!("expected the file variant: {d:?}") };
        assert_eq!(file.name, "Akira_1988.mkv");
        assert_eq!(file.size, 4096);
        assert_eq!(file.sha256, [0x07u8; 32]);
        assert_eq!(file.md5, [0x11u8; 16]);
        assert_eq!(file.mime.as_deref(), Some("video/x-matroska"));
        // Re-serialize and re-parse: hashes stay hex, the kind tag is stable, the variant round-trips.
        let json = serde_json::to_string(&ShareDescriptor::File(file.clone())).unwrap();
        assert!(json.contains("\"kind\":\"file\""), "kind tag must be present: {json}");
        assert!(json.contains(&hex::encode([0x07u8; 32])), "sha256 must serialize as hex: {json}");
        assert_eq!(ShareDescriptor::from_json_str(&json).unwrap(), ShareDescriptor::File(file));
    }

    #[test]
    fn file_ref_carries_the_hashes_without_computing() {
        let d = ShareDescriptor::from_json_str(&sample_file_json()).unwrap();
        let ShareDescriptor::File(file) = d else { panic!("expected file variant") };
        let fr = file.file_ref();
        assert_eq!(fr.sha256, file.sha256, "sha256 is carried, not recomputed");
        assert_eq!(fr.md5, file.md5, "md5 is carried, not recomputed");
        assert_eq!(fr.name, file.name);
        assert_eq!(fr.size, file.size);
    }

    #[test]
    fn into_file_ticket_uses_carried_facts() {
        let d = ShareDescriptor::from_json_str(&sample_file_json()).unwrap();
        let ShareDescriptor::File(file) = d else { panic!("expected file variant") };
        let sha = file.sha256;
        let ticket = file.into_file_ticket(Endpoint::default(), vec![0u8; 129], None, Nonce::mint());
        let fr = ticket.file_ref().expect("a File ticket yields its file_ref");
        assert_eq!(fr.sha256, sha);
        assert_eq!(fr.md5, [0x11u8; 16]);
    }

    #[test]
    fn folder_descriptor_parses_and_round_trips() {
        // Compute the matching root_hash for the entries so the descriptor is self-consistent.
        let entries = vec![
            ManifestEntry {
                rel_path: "Akira_1988.mkv".into(),
                size: 4096,
                sha256: [0x07; 32],
                md5: [0x11; 16],
                mode: 0o644,
            },
            ManifestEntry {
                rel_path: "subs/en.srt".into(),
                size: 128,
                sha256: [0x22; 32],
                md5: [0x33; 16],
                mode: 0o600,
            },
        ];
        let manifest = Manifest { v: manifest::MANIFEST_VERSION, entries };
        let bytes = manifest::encode(&manifest).unwrap();
        let root_hash: [u8; 32] = sha2::Sha256::digest(&bytes).into();

        let d = ShareDescriptor::from_json_str(&sample_folder_json(&hex::encode(root_hash))).unwrap();
        let ShareDescriptor::Folder(folder) = d else { panic!("expected folder variant") };
        assert_eq!(folder.name, "subs");
        assert_eq!(folder.root_hash, root_hash);
        assert_eq!(folder.entries.len(), 2);
        // Re-serialize and round-trip.
        let json = serde_json::to_string(&ShareDescriptor::Folder(folder.clone())).unwrap();
        assert!(json.contains("\"kind\":\"folder\""), "kind tag must be present: {json}");
        assert_eq!(ShareDescriptor::from_json_str(&json).unwrap(), ShareDescriptor::Folder(folder));
    }

    #[test]
    fn folder_into_ticket_mints_payload_folder_with_matching_root_hash() {
        // Build a self-consistent folder descriptor and mint a ticket; the ticket's payload carries
        // the FolderRef whose root_hash matches, and the manifest bytes come back for serving.
        let manifest_entry = ManifestEntry {
            rel_path: "a.bin".into(),
            size: 4,
            sha256: [0x07; 32],
            md5: [0x11; 16],
            mode: 0o644,
        };
        let manifest = Manifest { v: manifest::MANIFEST_VERSION, entries: vec![manifest_entry.clone()] };
        let bytes = manifest::encode(&manifest).unwrap();
        let root_hash: [u8; 32] = sha2::Sha256::digest(&bytes).into();

        let folder = FolderDescriptor {
            name: "x".into(),
            root_hash,
            entries: vec![FolderEntry::from(&manifest_entry)],
            link_assertion: None,
        };
        let (ticket, returned_bytes) = folder
            .into_folder_ticket(Endpoint::default(), vec![0u8; 129], None, Nonce::mint())
            .expect("a self-consistent descriptor mints a ticket");
        let fr = ticket.folder_ref().expect("a Folder ticket yields its folder_ref");
        assert_eq!(fr.root_hash, root_hash);
        assert_eq!(fr.name, "x");
        assert_eq!(returned_bytes, bytes, "the manifest bytes must come back byte-for-byte");
    }

    #[test]
    fn folder_descriptor_with_wrong_root_hash_refused() {
        // The descriptor's claimed root_hash does not match sha256(its entries); minting must
        // refuse — consistency-checking Hoardbook's own two claims, not originating a commitment.
        let entry = ManifestEntry {
            rel_path: "a.bin".into(),
            size: 4,
            sha256: [0x07; 32],
            md5: [0x11; 16],
            mode: 0o644,
        };
        let folder = FolderDescriptor {
            name: "x".into(),
            root_hash: [0xEE; 32], // deliberately wrong
            entries: vec![FolderEntry::from(&entry)],
            link_assertion: None,
        };
        let err = folder
            .into_folder_ticket(Endpoint::default(), vec![0u8; 129], None, Nonce::mint())
            .unwrap_err();
        assert!(err.to_string().contains("does not match"), "got: {err}");
    }

    #[test]
    fn malformed_json_is_reasoned_not_a_panic() {
        assert!(matches!(ShareDescriptor::from_json_str("not json"), Err(CoreError::Ticket(_))));
        // Wrong-length sha256 hex is refused too.
        let bad = sample_file_json().replace(&hex::encode([0x07u8; 32]), "0011");
        assert!(matches!(ShareDescriptor::from_json_str(&bad), Err(CoreError::Ticket(_))));
    }

    #[test]
    fn descriptor_without_kind_tag_refused() {
        // The seam is private (no Hoardbook yet); a flat M1-style descriptor without `"kind"` is
        // refused with a reasoned error, not silently accepted as a file.
        let flat = format!(
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
        );
        assert!(ShareDescriptor::from_json_str(&flat).is_err(), "a kind-less descriptor must be refused");
    }
}
