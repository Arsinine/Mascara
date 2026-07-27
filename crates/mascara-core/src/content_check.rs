//! The post-transfer content-type check (spec D7 / MT9, M3 brief §1, DESIGN.md §4): compare the
//! sender's **declared** `name`/`mime` against the type sniffed from the **actual bytes**. A
//! `FileRef`'s `mime` (and the extension implied by `name`) is a *claim, never proof* (MT9); the
//! sniff is the receiver's independent check that the bytes aren't lying about what they are.
//!
//! **The three-way verdict.** [`Verdict::Match`] — the sniff agrees with the claim;
//! [`Verdict::Mismatch`] — the sniff disagrees (e.g. `.mkv` name, `MZ` bytes ⇒ a PE executable
//! disguised as Matroska); [`Verdict::Unverifiable`] — the bytes have no magic-number signature
//! `infer` recognises (plain text, CSV, JSON — Open Q6). **`Unverifiable` is never a spoof
//! mismatch**: a signature-less file is exactly what a text file looks like, so refusing it as a
//! lie would penalise the innocent.
//!
//! **Policy knob (D7).** Default [`Policy::WarnAndAcknowledge`] — a `Mismatch` is surfaced for the
//! user to acknowledge (the sniff result is advisory; the hash already gate-kept integrity). A
//! settable [`Policy::HardRefuse`] turns `Mismatch` into a reasoned refusal ([`CoreError::Content`])
//! — the strict mode for hosts who want the gate to bite. `Match` and `Unverifiable` are unaffected
//! by the policy.
//!
//! **Offline by construction (`sem_contentcheck_offline`).** This module touches only the bytes it
//! is handed and the `infer` crate's static signature table — no I/O of any kind, no network, no
//! filesystem. It is a pure function of `(declared, bytes, policy)`.

use crate::error::CoreError;

/// The three-way verdict (DESIGN §4 / spec D7, MT9).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// The sniffed type agrees with the declared name (and the declared mime, if any).
    Match,
    /// The sniffed type disagrees with the declared name and/or mime. Advisory under
    /// [`Policy::WarnAndAcknowledge`]; a reasoned refusal under [`Policy::HardRefuse`].
    ///
    /// Carries the declared-vs-sniffed details for the caller's UX ("the file claims to be a .mkv
    /// but its bytes are a Windows executable").
    Mismatch {
        /// The extension the declared name implied, if any (lowercased, no dot).
        declared_ext: Option<String>,
        /// The declared mime, if the ticket carried one.
        declared_mime: Option<String>,
        /// The extension `infer` sniffed from the bytes, if any.
        sniffed_ext: Option<String>,
        /// The mime `infer` sniffed from the bytes, if any.
        sniffed_mime: Option<String>,
    },
    /// The bytes carry no magic-number signature `infer` recognises (plain text, CSV, JSON, …).
    /// **Never a mismatch** (Open Q6): signature-less is what an honest text file looks like, so the
    /// claim cannot be contradicted from the bytes alone. The caller surfaces this informational,
    /// not as a spoof warning.
    Unverifiable,
}

/// The policy knob (D7). The check is advisory-by-default in the MAS-INV-4 spirit — a mismatch is
/// surfaced and acknowledged, not silently fatal — with a settable strict mode that turns a
/// `Mismatch` into a refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Policy {
    /// Default: a [`Verdict::Mismatch`] is returned to the caller for acknowledgement. The hash
    /// already gate-kept integrity; the sniff is a separate, advisory claim-vs-bytes check.
    #[default]
    WarnAndAcknowledge,
    /// Strict: a [`Verdict::Mismatch`] becomes a [`CoreError::Content`] refusal.
    /// `Match` and `Unverifiable` are unaffected.
    HardRefuse,
}

/// Run the content-check over the actual bytes against the declared name (and optional mime).
///
/// `declared_name` is the `FileRef.name` (or a manifest entry's basename) — the extension is the
/// claim. `declared_mime` is the `FileRef.mime` the sender optionally carried; `None` means "no
/// claim was made", so only the name's extension is checked. `bytes` is the leading slice of the
/// file content (the whole file is not required — `infer` reads only the first ~8 KiB of magic
/// numbers; the caller may pass the whole buffer or a bounded head, both work).
///
/// Offline, allocation-free over the bytes (no copies, no I/O).
pub fn check(
    declared_name: &str,
    declared_mime: Option<&str>,
    bytes: &[u8],
    policy: Policy,
) -> Result<Verdict, CoreError> {
    let declared_ext = ext_of(declared_name);
    let sniffed = infer::get(bytes).map(|ty| (ty.extension().to_string(), ty.mime_type().to_string()));

    let verdict = match sniffed {
        // A signature was recognised — compare it against the declared name/mime.
        Some((sniffed_ext, sniffed_mime)) => {
            let ext_agrees = match &declared_ext {
                Some(de) => de.eq_ignore_ascii_case(&sniffed_ext),
                None => true, // no extension claim ⇒ nothing to contradict on the name side
            };
            let mime_agrees = match declared_mime {
                Some(dm) => dm.eq_ignore_ascii_case(&sniffed_mime),
                None => true, // no mime claim ⇒ nothing to contradict on the mime side
            };
            if ext_agrees && mime_agrees {
                Verdict::Match
            } else {
                Verdict::Mismatch {
                    declared_ext,
                    declared_mime: declared_mime.map(str::to_string),
                    sniffed_ext: Some(sniffed_ext),
                    sniffed_mime: Some(sniffed_mime),
                }
            }
        }
        // No signature recognised — plain text / CSV / unknown. Unverifiable, never a spoof (Q6).
        None => Verdict::Unverifiable,
    };

    // Hard-refuse converts a Mismatch into a reasoned refusal; Match/Unverifiable pass through.
    if matches!(verdict, Verdict::Mismatch { .. }) && matches!(policy, Policy::HardRefuse) {
        let Verdict::Mismatch {
            declared_ext,
            declared_mime,
            sniffed_ext,
            sniffed_mime,
        } = verdict
        else {
            unreachable!("guarded above")
        };
        return Err(CoreError::Content(format!(
            "sniffed type does not match the declared claim — declared ext={} mime={}, sniffed \
             ext={} mime={}; the strict policy refuses the transfer",
            declared_ext.as_deref().unwrap_or("(none)"),
            declared_mime.as_deref().unwrap_or("(none)"),
            sniffed_ext.as_deref().unwrap_or("(none)"),
            sniffed_mime.as_deref().unwrap_or("(none)"),
        )));
    }
    Ok(verdict)
}

/// The lowercased extension of `name` (the substring after the last `.`), or `None` if there is no
/// dot or the dot is the last char. `"a.mkv"` → `Some("mkv")`; `"README"` → `None`.
fn ext_of(name: &str) -> Option<String> {
    let dot = name.rfind('.')?;
    let ext = &name[dot + 1..];
    if ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real magic-number bytes for the sniff fixtures.
    // PE/Windows executable: starts with "MZ" (0x4d 0x5a).
    const PE_BYTES: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff";
    // JPEG: SOI marker 0xFF 0xD8 0xFF.
    const JPEG_BYTES: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F'];
    // No magic-number signature: plain ASCII text.
    const TEXT_BYTES: &[u8] = b"hello, world\nthis is a plain text file\n";
    // CSV (also signature-less).
    const CSV_BYTES: &[u8] = b"name,size\nfoo,42\nbar,1337\n";

    #[test]
    fn declared_matches_sniffed_passes() {
        // JPEG name over JPEG bytes ⇒ Match.
        let v = check("photo.jpg", Some("image/jpeg"), JPEG_BYTES, Policy::WarnAndAcknowledge).unwrap();
        assert_eq!(v, Verdict::Match, "got: {v:?}");
        // Match under HardRefuse is still Ok (the strict policy only bites on Mismatch).
        let v = check("photo.jpg", Some("image/jpeg"), JPEG_BYTES, Policy::HardRefuse).unwrap();
        assert_eq!(v, Verdict::Match);
    }

    #[test]
    fn declared_matches_without_mime_claim() {
        // No mime claim — the name's extension is the only claim, and it agrees.
        let v = check("photo.jpg", None, JPEG_BYTES, Policy::default()).unwrap();
        assert_eq!(v, Verdict::Match);
    }

    #[test]
    fn mkv_name_over_mz_bytes_is_mismatch() {
        // The classic spoof: .mkv name over a Windows executable body.
        let v = check(
            "Akira_1988.mkv",
            Some("video/x-matroska"),
            PE_BYTES,
            Policy::WarnAndAcknowledge,
        )
        .unwrap();
        match v {
            Verdict::Mismatch { declared_ext, declared_mime, sniffed_ext, sniffed_mime } => {
                assert_eq!(declared_ext.as_deref(), Some("mkv"));
                assert_eq!(declared_mime.as_deref(), Some("video/x-matroska"));
                assert_eq!(sniffed_ext.as_deref(), Some("exe"), "MZ is a PE executable: got {sniffed_ext:?}");
                assert!(sniffed_mime.as_deref().is_some(), "a sniffed mime must be present");
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    /// SEMANTIC_MODEL `sem_fileref_type_is_claim_not_trust` — the declared name/mime never bypass
    /// the sniff. In strict mode the `.mkv`→`MZ` spoof is a reasoned refusal, never an `Ok`.
    #[test]
    fn sem_fileref_type_is_claim_not_trust() {
        let err = check(
            "Akira_1988.mkv",
            Some("video/x-matroska"),
            PE_BYTES,
            Policy::HardRefuse,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Content(_)), "got: {err}");
        assert!(
            err.to_string().contains("sniffed type does not match"),
            "hard-refuse mismatch must carry a content reason: {err}"
        );

        // Sanity: the declared name alone (with no spoof) under HardRefuse still passes.
        let v = check("setup.exe", None, PE_BYTES, Policy::HardRefuse).unwrap();
        assert_eq!(v, Verdict::Match, "an honestly-named PE must Match even in strict mode");
    }

    #[test]
    fn no_signature_type_is_unverifiable_not_mismatch() {
        // Plain text / CSV bytes have no magic-number signature. The sniff returns None, which is
        // Unverifiable — NEVER a spoof mismatch (Open Q6), regardless of the declared name.
        for (name, bytes) in [("README.txt", TEXT_BYTES), ("data.csv", CSV_BYTES)] {
            let v = check(name, None, bytes, Policy::WarnAndAcknowledge).unwrap();
            assert_eq!(v, Verdict::Unverifiable, "{name}: signature-less bytes must be Unverifiable");
        }
        // Even a "lying" name over signature-less bytes is Unverifiable — the bytes can't contradict
        // a claim they have no signature to check against.
        let v = check("definitely-a-video.mkv", None, TEXT_BYTES, Policy::default()).unwrap();
        assert_eq!(v, Verdict::Unverifiable);
        // And Unverifiable is Unverifiable under HardRefuse too (strict mode only bites on Mismatch).
        let v = check("definitely-a-video.mkv", None, TEXT_BYTES, Policy::HardRefuse).unwrap();
        assert_eq!(v, Verdict::Unverifiable);
    }

    #[test]
    fn mime_only_mismatch_when_ext_absent() {
        // No extension on the name, but a mime claim that contradicts the sniff.
        let v = check("photo", Some("image/png"), JPEG_BYTES, Policy::default()).unwrap();
        assert!(matches!(v, Verdict::Mismatch { .. }), "got: {v:?}");
    }

    #[test]
    fn empty_and_tiny_buffers_are_unverifiable() {
        // An empty buffer or a 1-byte buffer carries no signature; Unverifiable, never a mismatch.
        let v = check("a.bin", None, &[], Policy::default()).unwrap();
        assert_eq!(v, Verdict::Unverifiable);
        let v = check("a.bin", None, &[0u8; 1], Policy::default()).unwrap();
        assert_eq!(v, Verdict::Unverifiable);
    }

    #[test]
    fn ext_of_helper() {
        assert_eq!(ext_of("a.mkv").as_deref(), Some("mkv"));
        assert_eq!(ext_of("a.MKV").as_deref(), Some("mkv"), "lowercased");
        assert_eq!(ext_of("a.b.mkv").as_deref(), Some("mkv"));
        assert_eq!(ext_of("README").as_deref(), None);
        assert_eq!(ext_of("trailing.").as_deref(), None, "trailing dot = no extension");
        assert_eq!(ext_of(".bashrc").as_deref(), Some("bashrc"));
    }

    /// SEMANTIC_MODEL `sem_contentcheck_offline` — this module performs no network I/O of any kind.
    /// Structural sweep: the module's **non-test** source (everything before `#[cfg(test)]`) names
    /// no network-y symbol. A future addition of `use std::net`, `use reqwest`, `use tokio::net`,
    /// etc. to the production code must trip this guard. Comment-stripped (like the M2 sweeps) so
    /// prose that *names* the guarantee doesn't self-trip. Only the non-test body is scanned, so the
    /// FORBIDDEN list itself (which lives in this test module) does not self-trip.
    #[test]
    fn sem_contentcheck_offline() {
        let src = include_str!("content_check.rs");
        // Scan only the production code: everything before the `#[cfg(test)]` block that opens this
        // module. (The FORBIDDEN list itself is inside the test module — scanning it would self-trip
        // on the very string we're looking for.)
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        let stripped: String = prod
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        const FORBIDDEN: [&str; 6] = [
            "use std::net",
            "use tokio::net",
            "use reqwest",
            "use ureq",
            "use hyper",
            "TcpStream",
        ];
        for sym in FORBIDDEN {
            assert!(
                !stripped.contains(sym),
                "sem_contentcheck_offline: content_check.rs names a network symbol `{sym}` — \
                 the sniff must be offline by construction"
            );
        }
    }

    // --- sniff sanity: pin the bytes the tests above rely on to the infer-recognised type, so a
    //     silent change to `infer`'s magic table fails loudly here instead of looking like a
    //     behaviour regression in the verdict tests. ---

    #[test]
    fn sniff_fixture_pe_is_executable() {
        let ty = infer::get(PE_BYTES).expect("infer must recognise MZ bytes as a PE");
        assert_eq!(ty.extension(), "exe", "got: {}", ty.extension());
    }

    #[test]
    fn sniff_fixture_jpeg_is_jpeg() {
        let ty = infer::get(JPEG_BYTES).expect("infer must recognise JPEG SOI bytes");
        assert_eq!(ty.extension(), "jpg");
    }

    #[test]
    fn sniff_fixture_text_has_no_signature() {
        assert!(infer::get(TEXT_BYTES).is_none(), "plain text must have no signature");
    }
}
