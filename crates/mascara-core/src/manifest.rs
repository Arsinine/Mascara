//! The folder manifest (M3 brief §1, DESIGN.md §4): the streamed file-list whose postcard bytes
//! are the commitment substrate for a folder ticket's `root_hash`. Each entry mirrors
//! [`crate::ticket::FileRef`]'s hash/size representations — sha256 + md5 + size — and adds the
//! manifest-relative path and a portable filesystem `mode`.
//!
//! **Hoardbook-precomputed (MR-13).** Mascara computes no content commitment — the manifest, like
//! a file's sha256, arrives from the sender already built. Core **never walks a directory tree** to
//! construct one (SEMANTIC_MODEL `sem_manifest_no_directory_walk`); it only **decodes and verifies**
//! a byte-form the sender supplied. Building one is the sender/Hoardbook's job; this module's public
//! API is decode + `root_hash` + verify.
//!
//! **Postcard bytes end-to-end (chorus H4).** postcard is deterministic for a fixed schema, so the
//! `root_hash` commitment (`sha256(manifest bytes)`) has exactly one byte-form — no JSON
//! whitespace/key-order/escaping ambiguity. That determinism is why postcard is `=`-pinned in the
//! workspace and why **every field below serializes positionally with no `#[serde(skip_serializing_if)]`
//! or Option trickery** (the M1 HANDOVER postcard gotcha): postcard is non-self-describing, so a
//! decode must read exactly the fields an encode wrote, in order, with no optional discriminants.
//!
//! **Caps (the brief).** A manifest is buffered in full before a single path is trusted, so its
//! byte length is a DoS surface. Two caps, both enforced in [`decode`]:
//! - **> 32 MiB hard-fails** with a reasoned error **before any allocation proportional to the
//!   claimed size** — a hostile sender cannot OOM the receiver by claiming a 4 GB postcard.
//! - **> 1.5 MiB soft-warns** — a distinguishable signal in [`DecodeOutcome`] the caller turns into
//!   a "redirect to Buddy Backup" notice (MR-12). A large manifest is a smell that the share should
//!   be a Buddy Pairing dataset (Phase 2), not a one-shot folder ticket.
//!
//! **Network-free (DESIGN §1).** No I/O of any kind here — pure bytes-in/bytes-out, unit-testable.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Schema discriminant for the manifest (mirrors `TICKET_VERSION` / `REGISTRY_VERSION`).
pub const MANIFEST_VERSION: u8 = 1;
/// Hard cap on the byte length of a manifest the receiver will buffer: a manifest is fully
/// buffered before any path is trusted (chorus H4 — a TOCTOU on the commitment otherwise), so its
/// length bounds the receiver's exposure. **32 MiB** (M3 brief).
pub const HARD_CAP_BYTES: usize = 32 * 1024 * 1024;
/// Soft-warn cap on the byte length (M3 brief; MR-12): above this the caller should redirect the
/// user to Buddy Backup. Decode still succeeds; the outcome carries the warning distinguishably.
pub const SOFT_WARN_BYTES: usize = 1024 * 1024 + 512 * 1024; // 1.5 MiB

/// One file in a folder manifest — the manifest-relative path plus the carried content commitment.
///
/// Hash/size field types and representations **mirror [`crate::ticket::FileRef`]** exactly so a
/// receiver can build a `FileRef` per entry without re-encoding: `sha256` as `[u8; 32]`, `md5` as
/// `[u8; 16]` (advisory legacy-catalog interop, MR-11; collision-broken, never a trust anchor),
/// `size` as `u64`. `mode` is a portable filesystem mode (the low permission bits the sender
/// recorded — `0o644`, `0o755`, etc.); Phase-2 neutralization (DESIGN §12.8) records the *original*
/// mode here while storing the file inert (`& ~0o111` on Unix).
///
/// **No `#[serde(skip_serializing_if)]`, no `Option`s** (postcard gotcha, M1 HANDOVER): every field
/// serializes positionally so decode reads exactly what encode wrote.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Manifest-relative POSIX path (`"subdir/file.mp4"`, never absolute, never `..` — receiver-side
    /// path guards live in `mascara-net::engine`, M3 stage 2). Stored as a plain string so postcard
    /// length-prefixes it without any path-encoding ambiguity.
    pub rel_path: String,
    pub size: u64,
    /// Content commitment, sender-precomputed (MR-13). Carried, never computed here.
    pub sha256: [u8; 32],
    /// Advisory legacy-catalog interop hash (MR-11). Carried, never computed here.
    pub md5: [u8; 16],
    /// Portable filesystem mode bits (e.g. `0o644`). Plain `u32` — no platform-specific newtype at
    /// this layer; the byte-form is frozen as a positional varint-encoded u32.
    pub mode: u32,
}

/// The manifest: a schema version + the entries. The version discriminant mirrors the ticket and
/// registry conventions — an opener refuses a version it does not recognise (recognise-and-refuse).
///
/// The entries are a `Vec`, not a map: postcard serializes a `Vec` as a length-prefixed sequence of
/// positional records, and the `root_hash` commits to that exact byte layout (entry order included).
/// A sender who re-orders entries produces a different (still-valid) `root_hash`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u8,
    pub entries: Vec<ManifestEntry>,
}

impl Default for Manifest {
    fn default() -> Self {
        Manifest { v: MANIFEST_VERSION, entries: Vec::new() }
    }
}

/// The decode outcome — the soft-warn signal is distinguishable from a clean decode (M3 brief),
/// so the caller (CLI/GUI) can surface "redirect to Buddy Backup" (MR-12) without re-checking the
/// byte length. The hard cap is a reasoned `Err`, not an outcome variant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeOutcome {
    /// Decoded cleanly and under the soft-warn cap.
    Ok(Manifest),
    /// Decoded cleanly, but the byte length exceeded the soft-warn cap — the caller should redirect
    /// the user to Buddy Backup (MR-12). Still under the hard cap (else [`CoreError::Manifest`]).
    OkWithSoftWarn(Manifest),
}

impl DecodeOutcome {
    /// The decoded manifest, regardless of whether the soft-warn fired.
    pub fn into_manifest(self) -> Manifest {
        match self {
            DecodeOutcome::Ok(m) | DecodeOutcome::OkWithSoftWarn(m) => m,
        }
    }

    /// True if the soft-warn cap fired on this decode.
    pub fn is_soft_warn(&self) -> bool {
        matches!(self, DecodeOutcome::OkWithSoftWarn(_))
    }
}

/// Encode a manifest to its deterministic postcard byte-form (chorus H4 — exactly one byte-form per
/// schema+contents, the substrate `root_hash` commits to). Errors are encoding failures only; the
/// byte length is whatever the contents produce (no cap on encode — the cap is a receive-side DoS
/// guard, not a property of the sender's own manifest).
pub fn encode(manifest: &Manifest) -> Result<Vec<u8>, CoreError> {
    postcard::to_stdvec(manifest)
        .map_err(|e| CoreError::Manifest(format!("could not encode manifest: {e}")))
}

/// Compute the folder commitment: `sha256(manifest bytes)` (DESIGN §4 / chorus H4). The receiver
/// buffers the full manifest, hashes the bytes, and compares against the ticket's `folder_ref.root_hash`
/// **before** trusting a single path in it. Defined over the encoded bytes so the commitment is
/// byte-form-stable, not struct-stable.
pub fn root_hash(manifest: &Manifest) -> Result<[u8; 32], CoreError> {
    let bytes = encode(manifest)?;
    Ok(Sha256::digest(&bytes).into())
}

/// Verify a manifest against an expected `root_hash` — `sha256(bytes) == expected`. A mismatch is a
/// reasoned error (chorus H4 — the byte-form the sender committed to differs from what arrived; do
/// not act on a single path in the manifest). Callers should prefer [`decode_and_verify`], which
/// runs the cap check + decode + verify in one call.
pub fn verify(manifest: &Manifest, expected_root_hash: &[u8; 32]) -> Result<(), CoreError> {
    let actual = root_hash(manifest)?;
    if &actual != expected_root_hash {
        return Err(CoreError::Manifest(format!(
            "manifest root_hash mismatch: expected {}, got {} — the byte-form was tampered with or \
             re-ordered; refusing to act on any path in it",
            hex::encode(expected_root_hash),
            hex::encode(actual),
        )));
    }
    Ok(())
}

/// Decode a manifest byte-form, enforcing both caps. **The hard cap is checked before any
/// allocation proportional to the claimed size** (M3 brief — a hostile sender's 4 GB postcard must
/// not OOM the receiver before the refusal lands). Returns a reasoned `Err` on:
/// - byte length > [`HARD_CAP_BYTES`] (checked before allocation);
/// - a postcard decode failure;
/// - a schema-version mismatch (`v != MANIFEST_VERSION`).
///
/// Returns [`DecodeOutcome::Ok`] under the soft-warn cap, [`DecodeOutcome::OkWithSoftWarn`] above
/// it (still under the hard cap).
pub fn decode(bytes: &[u8]) -> Result<DecodeOutcome, CoreError> {
    // Hard cap BEFORE any allocation proportional to the claimed size. `postcard::from_bytes` would
    // happily grow a Vec to the claimed length (up to `isize::MAX`); the cap turns that into a
    // bounded, reasoned refusal (chorus: length caps checked before allocation).
    if bytes.len() > HARD_CAP_BYTES {
        return Err(CoreError::Manifest(format!(
            "manifest is {} bytes — over the {} hard cap; refusing before allocation",
            bytes.len(),
            human_bytes(HARD_CAP_BYTES),
        )));
    }
    let manifest: Manifest = postcard::from_bytes(bytes)
        .map_err(|e| CoreError::Manifest(format!("could not decode manifest: {e}")))?;
    if manifest.v != MANIFEST_VERSION {
        return Err(CoreError::Manifest(format!(
            "unsupported manifest version {} (this Mascara understands v{MANIFEST_VERSION})",
            manifest.v
        )));
    }
    if bytes.len() > SOFT_WARN_BYTES {
        Ok(DecodeOutcome::OkWithSoftWarn(manifest))
    } else {
        Ok(DecodeOutcome::Ok(manifest))
    }
}

/// Decode + verify in one call — the receiver-side flow (DESIGN §4): cap-check → decode →
/// `sha256(bytes) == expected_root_hash`. The hash is over the *supplied* bytes, not a re-encoding,
/// so a byte-form that does not match the commitment is refused even if it re-parses to a struct
/// that "looks right" (a TOCTOU on the commitment, chorus H4).
pub fn decode_and_verify(
    bytes: &[u8],
    expected_root_hash: &[u8; 32],
) -> Result<DecodeOutcome, CoreError> {
    // Cap + decode first (cheap refusal on hostile input), then verify the hash over the bytes.
    let outcome = decode(bytes)?;
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if &actual != expected_root_hash {
        return Err(CoreError::Manifest(format!(
            "manifest root_hash mismatch: expected {}, got {} — the byte-form was tampered with or \
             re-ordered; refusing to act on any path in it",
            hex::encode(expected_root_hash),
            hex::encode(actual),
        )));
    }
    Ok(outcome)
}

/// Format a byte count as a small human-readable string for error messages ("32 MiB", "1.5 MiB").
fn human_bytes(n: usize) -> String {
    let mib = n as f64 / (1024.0 * 1024.0);
    format!("{:.0} MiB", mib)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, size: u64, seed: u8) -> ManifestEntry {
        ManifestEntry {
            rel_path: path.into(),
            size,
            sha256: [seed; 32],
            md5: [seed; 16],
            mode: 0o644,
        }
    }

    fn sample() -> Manifest {
        Manifest {
            v: MANIFEST_VERSION,
            entries: vec![
                entry("Akira_1988.mkv", 4096, 7),
                entry("subs/en.srt", 128, 0x11),
            ],
        }
    }

    // --- the core four: round-trip, root_hash verify, tamper refused, determinism ---

    #[test]
    fn encode_decode_round_trip() {
        let m = sample();
        let bytes = encode(&m).unwrap();
        let decoded = decode(&bytes).unwrap().into_manifest();
        assert_eq!(decoded, m);
    }

    #[test]
    fn root_hash_verification_passes_on_good_bytes() {
        let m = sample();
        let root = root_hash(&m).unwrap();
        // The hash over the encoded bytes matches verify().
        verify(&m, &root).expect("a manifest verifies against its own root_hash");
        // And decode_and_verify accepts the matching bytes.
        let bytes = encode(&m).unwrap();
        assert!(matches!(decode_and_verify(&bytes, &root).unwrap(), DecodeOutcome::Ok(_)));
    }

    #[test]
    fn tampered_bytes_refused() {
        let m = sample();
        let root = root_hash(&m).unwrap();
        let mut bytes = encode(&m).unwrap();
        // Flip one byte deep in the body — still decodes (or fails to), but the hash must catch it.
        let i = bytes.len() / 2;
        bytes[i] ^= 0xff;
        let err = decode_and_verify(&bytes, &root).unwrap_err();
        assert!(matches!(err, CoreError::Manifest(_)), "got: {err}");
        assert!(
            err.to_string().contains("root_hash mismatch"),
            "tamper must be reported as a root_hash mismatch: {err}"
        );
    }

    #[test]
    fn determinism_same_entries_same_bytes() {
        let m1 = sample();
        let m2 = sample();
        // The same entry list encodes to identical bytes (chorus H4 — one byte-form).
        assert_eq!(encode(&m1).unwrap(), encode(&m2).unwrap());
        // Re-ordering entries produces a different (still valid) commitment — entry order is part
        // of the committed byte-form.
        let mut reordered = m1.clone();
        reordered.entries.reverse();
        assert_ne!(encode(&reordered).unwrap(), encode(&m1).unwrap());
    }

    /// SEMANTIC_MODEL `sem_manifest_cap_enforced` — a byte length over the 32 MiB hard cap is
    /// refused **before any allocation proportional to the claimed size**. The body claims a huge
    // Vec length via postcard's varint, but the byte length already trips the cap and we never reach
    // the decoder.
    #[test]
    fn sem_manifest_cap_enforced() {
        // A buffer exactly at the cap decodes (or fails for a structural reason — it's not the cap);
        // one byte over is a reasoned cap refusal.
        let at_cap = vec![0u8; HARD_CAP_BYTES];
        let over_cap = vec![0u8; HARD_CAP_BYTES + 1];
        // The at-cap buffer won't decode as a valid manifest (it's all zeros) but the error must NOT
        // be the cap — it's a decode error, which means we got past the cap check without refusing.
        let at_err = decode(&at_cap).unwrap_err();
        assert!(
            !at_err.to_string().contains("hard cap"),
            "at-cap must not trip the cap (got: {at_err})"
        );
        // One byte over trips the cap, BEFORE the all-zeros body is touched.
        let over_err = decode(&over_cap).unwrap_err().to_string();
        assert!(over_err.contains("hard cap"), "over-cap must trip the cap: {over_err}");
    }

    #[test]
    fn soft_warn_fires_above_1_5_mib() {
        // Build a manifest just large enough that its encoded form exceeds the soft-warn cap but
        // stays well under the hard cap. Each entry is ~67 bytes postcard; 25_000 entries ≈ 1.6 MiB.
        let entries: Vec<ManifestEntry> = (0..25_000)
            .map(|i| entry(&format!("file_{i:05}.bin"), i as u64, (i as u8).wrapping_mul(7)))
            .collect();
        let m = Manifest { v: MANIFEST_VERSION, entries };
        let bytes = encode(&m).unwrap();
        assert!(
            bytes.len() > SOFT_WARN_BYTES,
            "test fixture must actually exceed the soft-warn cap ({} bytes)",
            bytes.len()
        );
        assert!(bytes.len() <= HARD_CAP_BYTES, "test fixture must stay under the hard cap");
        assert!(
            matches!(decode(&bytes).unwrap(), DecodeOutcome::OkWithSoftWarn(_)),
            "a manifest > 1.5 MiB must decode to OkWithSoftWarn"
        );

        // And a small manifest decodes to plain Ok.
        let small = encode(&sample()).unwrap();
        assert!(
            small.len() <= SOFT_WARN_BYTES,
            "sample fixture must be under the soft-warn cap ({} bytes)",
            small.len()
        );
        assert!(matches!(decode(&small).unwrap(), DecodeOutcome::Ok(_)));
    }

    #[test]
    fn unknown_version_refused() {
        let mut m = sample();
        m.v = 2;
        let bytes = encode(&m).unwrap();
        let err = decode(&bytes).unwrap_err().to_string();
        assert!(err.contains("unsupported manifest version 2"), "got: {err}");
    }

    #[test]
    fn empty_manifest_round_trips_and_hashes() {
        let m = Manifest::default();
        let bytes = encode(&m).unwrap();
        assert!(bytes.len() <= SOFT_WARN_BYTES);
        let decoded = decode(&bytes).unwrap().into_manifest();
        assert_eq!(decoded, m);
        // root_hash is defined and stable for an empty manifest too.
        let root = root_hash(&m).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(root, digest);
    }

    /// SEMANTIC_MODEL `sem_manifest_byte_form_frozen` — golden vector over the manifest's postcard
    /// byte-form. The M3 folder `root_hash` commitment rests on this byte-form exactly the way the
    /// M1 ticket body rests on `sem_ticket_body_postcard_frozen`; a postcard bump or a schema
    /// re-order must break here loudly instead of silently orphaning every folder commitment. A
    /// legitimate manifest schema change bumps `MANIFEST_VERSION` and re-freezes this vector in the
    /// same PR (SEMANTIC_MODEL rule 1).
    #[test]
    fn sem_manifest_byte_form_frozen() {
        let m = Manifest {
            v: MANIFEST_VERSION,
            entries: vec![
                ManifestEntry {
                    rel_path: "Akira_1988.mkv".into(),
                    size: 4096,
                    sha256: [7u8; 32],
                    md5: [0x11u8; 16],
                    mode: 0o644,
                },
                ManifestEntry {
                    rel_path: "subs/en.srt".into(),
                    size: 128,
                    sha256: [0x22u8; 32],
                    md5: [0x33u8; 16],
                    mode: 0o600,
                },
            ],
        };
        let bytes = encode(&m).unwrap();
        // The byte-form a folder `root_hash` would commit to. Frozen on 2026-07-23 against
        // postcard =1.1.3 — the exact output of `postcard::to_stdvec` for the schema above.
        assert_eq!(
            hex::encode(&bytes),
            "01020e416b6972615f313938382e6d6b768020070707070707070707070707070707070707070707070707070707070707070711111111111111111111111111111111a4030b737562732f656e2e73727480012222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333338003",
            "manifest body byte layout drifted"
        );
        // And the frozen bytes still decode to the same manifest (round-trip, not just encode).
        assert_eq!(decode(&bytes).unwrap().into_manifest(), m);
        // The root_hash of the frozen vector — a fixed value, committed to here so a byte-form
        // change also surfaces as a root_hash change (which is what a folder ticket would notice).
        let root: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(
            hex::encode(root),
            "c1a13fee58a9a95e2faec8b8ccd3e2faeb8554b44d2524e102fc20bfcb02b64d",
            "root_hash of the frozen manifest drifted — a folder ticket would now commit to a \
             different hash"
        );
    }
}
