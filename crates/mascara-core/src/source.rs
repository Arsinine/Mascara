//! Serve-time source check (MR-14 step 2, spec D34): before any bytes stream, the sender verifies
//! the ticketed source is still **present** and cheaply **unchanged** — fs metadata only, NO
//! hashing, NO byte reads (Mascara computes no content commitment, MR-13; the receiver's
//! end-to-end sha256 is the authoritative backstop, MR-14 step 3). A missing/changed source fails
//! honestly *before* streaming, never mid-stream.
//!
//! `FileRef`'s postcard layout is frozen (no mtime field), so **size mismatch is the cheap
//! staleness signal**; a same-size content change is caught by the receiver's hash. Pure and
//! network-free: the M2 listener (`mascara-net`) calls [`check_source`] in its serve path — that
//! wiring is what converts `sem_serve_verifies_source_present` to ENFORCED.

use std::path::Path;

use crate::ticket::FileRef;

/// The three-way verdict of the MR-14 serve-time source check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceCheck {
    /// Present and size matches the ticket's `FileRef` — servable.
    Ok,
    /// The path does not exist, is not readable, or is not a regular file.
    Missing,
    /// Present, but its size no longer matches the ticket — the source changed since issue.
    Changed { expected: u64, actual: u64 },
}

/// Check the filesystem against the ticket's existing `FileRef` facts — metadata only, O(1).
#[must_use]
pub fn check_source(path: &Path, file_ref: &FileRef) -> SourceCheck {
    match std::fs::metadata(path) {
        Err(_) => SourceCheck::Missing,
        Ok(md) if !md.is_file() => SourceCheck::Missing,
        Ok(md) if md.len() != file_ref.size => {
            SourceCheck::Changed { expected: file_ref.size, actual: md.len() }
        }
        Ok(_) => SourceCheck::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_ref(size: u64) -> FileRef {
        FileRef { name: "a.bin".into(), size, sha256: [7u8; 32], md5: [0x11u8; 16], mime: None }
    }

    /// MR-14: an unchanged source (present, size matches) is servable.
    #[test]
    fn unchanged_source_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.bin");
        std::fs::write(&path, [0u8; 16]).unwrap();
        assert_eq!(check_source(&path, &file_ref(16)), SourceCheck::Ok);
    }

    /// MR-14: a missing source is refused before any bytes stream.
    #[test]
    fn missing_source_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_source(&dir.path().join("gone.bin"), &file_ref(16)), SourceCheck::Missing);
        // A directory where the file should be is equally unservable.
        assert_eq!(check_source(dir.path(), &file_ref(16)), SourceCheck::Missing);
    }

    /// MR-14: size drift is the cheap staleness signal — refused, with both sizes reported.
    #[test]
    fn changed_source_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.bin");
        std::fs::write(&path, [0u8; 20]).unwrap();
        assert_eq!(
            check_source(&path, &file_ref(16)),
            SourceCheck::Changed { expected: 16, actual: 20 }
        );
    }
}
