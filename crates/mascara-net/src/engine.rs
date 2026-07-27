//! Single-file and folder pull orchestration — the client half of `/mascara/xfer/1` (DESIGN
//! §4/§6). Mining map: the quarry's `download_file_inner` progress/cancel shape → here, with the
//! full-file re-read hash replaced by an incremental one (D-resume keeps the offset seam for M3;
//! M2 always pulls from 0).
//!
//! Written against generic `AsyncRead+AsyncWrite` so the exact same logic runs over
//! `tokio::io::duplex` in tests and a real iroh `RecvStream`/`SendStream` in production — the
//! iroh-specific glue (opening the bi-stream, translating a QUIC close code) lives in `dialer.rs`.
//!
//! **M3 stage 3.** Folder flow (DESIGN §4/§5): [`fetch_manifest`] is one bi-stream that buffers
//! the whole manifest, **refuses `total > 32 MiB` BEFORE allocating**, decodes, and **verifies
//! `sha256(bytes) == folder_ref.root_hash` BEFORE returning any entry to the caller**
//! (`sem_folderref_manifest_verified_before_use` — TOCTOU guard, chorus H4); it also caches the
//! verified bytes at the receiver for resume. [`pull_folder`] is sequential per-file `file` ops,
//! each hash-verified via the existing [`pull_file`] machinery with a per-entry `FileRef`.
//! [`safe_rel_path`] is the receiver-side path guard for manifest entries
//! (`sem_folder_paths_guarded`, chorus H5) — the authenticated `root_hash` commits to bytes, not
//! path safety, so a malicious sender can notarize `../../etc/passwd` with a valid hash; the guard
//! fires before ANY filesystem op per entry.
//!
//! **Resume (D-resume, chorus H3/FQ3).** In [`pull_file`]: if `<name>.part` exists in the
//! destination, re-hash it from byte 0 into the incremental SHA-256 state and request
//! `offset = partial length`, appending to the partial; `offset == size` skips the network read
//! and goes straight to hash-verify; a final-hash mismatch (sender's file changed between
//! attempts) DELETES the partial and surfaces "file changed on the sender's side — restart". The
//! M2-era "delete the partial on every error" is **deliberately reversed for
//! `NetError::ConnectionLost`** (DESIGN §6.2: "aborts the transfer immediately (partial kept —
//! resume applies)") — cancel, hash mismatch, refusals, and unrecoverable local errors still
//! delete it (`sem_partials_deleted_on_cancel`).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use mascara_core::{
    decode_and_verify_manifest, FileRef, FolderRef, Manifest, ManifestEntry, Nonce,
};

use crate::error::NetError;
use crate::listener::{MAX_MANIFEST_FRAME, MAX_REQUEST_FRAME, Op, Request};

/// The protocol version this milestone speaks (DESIGN §4).
pub const PROTOCOL_VERSION: u8 = 1;

// --------------------------------------------------------------------------------------------
// Path guards — receiver-side (chorus H5). Single-file form + folder-manifest form.
// --------------------------------------------------------------------------------------------

/// A ticket's declared filename is **sender-controlled** — it must name one file *inside* the
/// chosen destination, never escape it. Accept only a single plain filename component; reject
/// empty, `.`/`..`, path separators (either slash — a `\` is a legal char on Unix but a separator
/// on the sender's Windows box), and absolute/rooted/drive/UNC forms — **before** any filesystem
/// operation. This is the single-file form of the chorus H5 path guard; the folder-manifest form
/// is [`safe_rel_path`]. Returns the safe name on success.
fn safe_filename(name: &str) -> Result<&str, NetError> {
    let refuse = |why: &str| -> Result<&str, NetError> {
        Err(NetError::Protocol(format!(
            "refusing the ticket's filename {name:?}: {why} — a received file must land inside the \
             chosen directory, never escape it"
        )))
    };
    if name.is_empty() {
        return refuse("empty name");
    }
    if name == "." || name == ".." {
        return refuse("a relative directory reference");
    }
    if name.contains('/') || name.contains('\\') {
        return refuse("contains a path separator");
    }
    // A leading drive-letter (`C:evil`) is a Windows rooted/drive-relative path, but a non-Windows
    // `Path` parses it as an ordinary component — reject it host-independently so a file received
    // on Linux can't carry a name that escapes once it reaches a Windows box.
    if has_drive_letter(name) {
        return refuse("a Windows drive-letter path");
    }
    // ANY colon, not just a drive letter: `report:payload` is an NTFS alternate-data-stream
    // reference that writes a hidden stream on `report` instead of a file (codex #2). Rejected
    // host-independently — a name received on Linux must not become an ADS write on Windows.
    if name.contains(':') {
        return refuse("contains a colon (a Windows alternate-data-stream reference)");
    }
    if is_windows_reserved_name(name) {
        return refuse("a Windows reserved device name");
    }
    // Windows silently strips trailing dots/spaces, so `evil.txt.` and `evil.txt ` both resolve to
    // `evil.txt` — a name that passes a distinctness check here but collides on landing.
    if name.ends_with('.') || name.ends_with(' ') {
        return refuse("ends with a dot or space (silently stripped on Windows)");
    }
    // Catch any remaining rooted/UNC forms: the name must resolve to exactly one *normal* path
    // component equal to the whole string.
    let mut comps = Path::new(name).components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(only)), None) if only.to_str() == Some(name) => Ok(name),
        _ => refuse("not a single plain filename component"),
    }
}

/// A manifest entry's `rel_path` is **sender-controlled and authenticated only by `root_hash`**,
/// which commits to the manifest *bytes*, not path safety — a malicious sender can notarize
/// `../../etc/passwd` with their own valid hash. [`safe_rel_path`] is the receiver-side guard that
/// fires BEFORE any filesystem op per entry (`sem_folder_paths_guarded`, chorus H5). Accepts a
/// POSIX-relative path with one or more normal components separated by `/` (subdir paths OK);
/// rejects empty, absolute/rooted (either OS), `..` or `.` components, `\` as separator or in a
/// name, drive-letter forms, Windows reserved names (`CON`/`PRN`/`AUX`/`NUL`/`COM1`–9/`LPT1`–9,
/// case-insensitive, with or without extension), and any non-Normal component. Returns the parsed
/// rel-path (verified to be all-Normal) on success.
///
/// Kept beside [`safe_filename`] (the single-file form) — same reasoned-refusal style. The two are
/// distinct because the folder form must allow `/`-separated sub-paths while the single-file form
/// must not.
fn safe_rel_path(rel: &str) -> Result<&str, NetError> {
    let refuse = |why: &str| -> Result<&str, NetError> {
        Err(NetError::Protocol(format!(
            "refusing the manifest path {rel:?}: {why} — a received folder entry must land inside \
             the chosen directory, never escape it"
        )))
    };
    if rel.is_empty() {
        return refuse("empty path");
    }
    if rel.starts_with('/') {
        return refuse("absolute (POSIX-rooted) path");
    }
    // `\` is a separator on the sender's Windows box and illegal in a name on POSIX — reject it
    // outright (a legit POSIX rel-path uses only `/`).
    if rel.contains('\\') {
        return refuse("contains a backslash (path separator on Windows)");
    }
    // Reject `.`/`..` components by splitting on `/` — Rust's `Path::components()` SKIPS `.` by
    // default, so it can't be relied on to catch them. An empty segment (double `/`) is also a
    // refusal (it would collapse on POSIX, hiding a path the sender wrote deliberately).
    for seg in rel.split('/') {
        if seg.is_empty() {
            return refuse("contains an empty component (leading/trailing/double `/`)");
        }
        if seg == "." || seg == ".." {
            return refuse("contains a `.` or `..` component");
        }
        if has_drive_letter(seg) {
            return refuse("contains a Windows drive-letter component");
        }
        // ANY colon (codex #2): `sub/report:payload` writes an NTFS alternate data stream on
        // `report` rather than a file — a hidden write the lexical guard must refuse.
        if seg.contains(':') {
            return refuse("contains a colon (a Windows alternate-data-stream reference)");
        }
        if is_windows_reserved_name(seg) {
            return refuse("contains a Windows reserved device name");
        }
        // Trailing dots/spaces are silently stripped by Windows (`sub./x` → `sub/x`).
        if seg.ends_with('.') || seg.ends_with(' ') {
            return refuse("has a component ending in a dot or space (stripped on Windows)");
        }
    }
    // Final defense-in-depth: every `Path::components()` entry must be Normal (catches any
    // platform-specific RootDir/PrefixDir the string scan above didn't).
    for comp in Path::new(rel).components() {
        if !matches!(comp, std::path::Component::Normal(_)) {
            return refuse("contains a non-Normal component (absolute, prefix, or `.`/`..`)");
        }
    }
    Ok(rel)
}

/// `true` if `name` begins with a Windows drive-letter prefix (`C:` / `c:`).
fn has_drive_letter(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

/// `true` if `name` (case-insensitive, with or without a file extension) is one of the Windows
/// reserved device names — `CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`. Such a name
/// on a Windows box resolves to a device, not a file (chorus H5). The check is host-independent
/// so a folder received on Linux cannot carry a name that escapes once it reaches a Windows box.
fn is_windows_reserved_name(name: &str) -> bool {
    let stem = match name.rsplit_once('.') {
        Some((stem, _)) => stem,
        None => name,
    };
    let upper = stem.to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.contains(&upper.as_str())
}

// --------------------------------------------------------------------------------------------
// Single-file pull (with resume).
// --------------------------------------------------------------------------------------------

/// Pull one file over an already-open bi-directional stream: send the request, stream the
/// response into `<dest_dir>/<name>.part` with incremental SHA-256, verify the final hash
/// against `file_ref.sha256` **before** renaming into place — the hash gate is what makes the
/// file "available" (`sem_fileref_hash_verified_before_available`); a mismatch discards the
/// partial. A name collision on the final rename gets a numeric suffix (`name (2).ext`) — never
/// an overwrite. `on_progress(done, total)` fires after every chunk (no UI coupling).
///
/// **Resume (D-resume, M3 stage 3).** If `<name>.part` already exists in `dest_dir`, it is
/// re-hashed from byte 0 into the incremental SHA-256 state and `offset = partial length` is
/// requested; the tail bytes are appended to the partial, and the final hash covers the WHOLE
/// file. `offset == size` skips the network read and goes straight to hash-verify. A final-hash
/// mismatch means the sender's file changed between attempts — the partial is DELETED and a
/// "file changed on the sender's side — restart" error is surfaced.
///
/// **`.part` retention by error class (DESIGN §6.2).** M2 deleted the `.part` on EVERY error
/// exit. M3's resume requires the partial to SURVIVE a connection loss: a
/// [`NetError::ConnectionLost`] (a network drop, NOT a peer cancel) KEEPS the `.part` (resumable);
/// explicit cancel ([`NetError::Cancelled`]), [`NetError::HashMismatch`], refusals, and
/// unrecoverable local errors still DELETE it (`sem_partials_deleted_on_cancel` still holds for
/// cancel).
pub async fn pull_file(
    send: impl AsyncWrite + Unpin,
    recv: impl AsyncRead + Unpin,
    nonce: Nonce,
    file_ref: &FileRef,
    requested_offset: u64,
    dest_dir: &Path,
    on_progress: impl FnMut(u64, u64),
) -> Result<PathBuf, NetError> {
    // For a single-file ticket the wire path IS the local name; `pull_entry` (folders) requests
    // the manifest rel-path on the wire while landing the leaf locally.
    let wire_path = file_ref.name.clone();
    pull_file_inner(send, recv, nonce, &wire_path, file_ref, requested_offset, dest_dir, on_progress).await
}

/// The wire/streaming half shared by [`pull_file`] and [`pull_entry`]: `wire_path` is what the
/// request names on the protocol (a single-file ticket's filename, or a folder entry's
/// manifest rel-path — the listener matches manifest ENTRIES, not leaves); `file_ref.name` is the
/// LOCAL destination name. The two coincide for single-file pulls and differ for subdir folder
/// entries (M3 stage-3b fix — requesting the leaf made every subdir entry "not in this folder's
/// manifest").
#[allow(clippy::too_many_arguments)]
async fn pull_file_inner(
    mut send: impl AsyncWrite + Unpin,
    mut recv: impl AsyncRead + Unpin,
    nonce: Nonce,
    wire_path: &str,
    file_ref: &FileRef,
    requested_offset: u64,
    dest_dir: &Path,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<PathBuf, NetError> {
    // The caller may pass an explicit offset (resume); pull_file also detects an existing `.part`
    // and re-hashes it. The caller-supplied offset wins when both apply (dialer's resume path
    // pre-computes the partial length); the engine's own `.part` detection covers the simple
    // "retry the same pull" case where no offset was passed.
    let name = safe_filename(&file_ref.name)?;
    std::fs::create_dir_all(dest_dir)?;
    let part_path = dest_dir.join(format!("{name}.part"));

    // If the caller did not pass an offset but a `.part` exists, resume: re-hash the partial from
    // byte 0 (the incremental hash must cover the WHOLE file) and request `offset = its length`.
    // A `.part` whose length is already the full size short-circuits to hash-verify.
    let (offset, mut prehash) = if requested_offset > 0 {
        (requested_offset, None)
    } else {
        match compute_partial_state(&part_path, file_ref.size) {
            PartialState::Absent => (0, None),
            PartialState::Resumable { len, hasher } => (len, Some(hasher)),
            // The partial already holds the whole file: re-hash it so the final-hash check covers
            // the existing bytes, then request `offset = size` (0 remaining) — straight to verify.
            PartialState::Complete { hasher } => (file_ref.size, Some(hasher)),
        }
    };

    // EVERY exit below this point runs through the retention match at the end — including the
    // refusal path, which previously returned early and stranded a pre-existing `.part` (codex #6).
    let streamed = async {
        let req =
            Request { v: PROTOCOL_VERSION, nonce, op: Op::File { path: wire_path.to_string(), offset } };
        let bytes = serde_json::to_vec(&req)
            .map_err(|e| NetError::Protocol(format!("could not encode request: {e}")))?;
        send.write_u32_le(bytes.len() as u32).await?;
        send.write_all(&bytes).await?;
        send.shutdown().await?;

        let status = recv.read_u8().await?;
        if status != 0 {
            // The error frame is sender-controlled — cap it before allocating, the client-side
            // mirror of the listener's `MAX_REQUEST_FRAME` gate, so a hostile peer can't provoke a
            // 4 GiB allocation with an oversized length prefix.
            let elen = recv.read_u32_le().await? as usize;
            if elen > MAX_REQUEST_FRAME {
                return Err(NetError::Protocol(format!(
                    "the sender's error message is too large ({elen} bytes, cap {MAX_REQUEST_FRAME} bytes)"
                )));
            }
            let mut ebuf = vec![0u8; elen];
            recv.read_exact(&mut ebuf).await?;
            return Err(NetError::Refused(String::from_utf8_lossy(&ebuf).into_owned()));
        }
        let remaining = recv.read_u64_le().await?;
        // The ticket already states the file's size, so the ONLY consistent response is exactly
        // the bytes from `offset` to the end. Bind `remaining` to it (codex #4): a hostile server
        // claiming `remaining = u64::MAX` no longer streams until the disk fills — it is refused
        // here, before a single byte is written. (This subsumes the earlier `checked_add` overflow
        // guard: an inconsistent total can never reach the arithmetic.)
        if offset > file_ref.size {
            return Err(NetError::Protocol(format!(
                "resume offset {offset} exceeds the ticket's declared size {} — refusing",
                file_ref.size
            )));
        }
        let expected = file_ref.size - offset;
        if remaining != expected {
            return Err(NetError::Protocol(format!(
                "the sender's response is inconsistent with the ticket: it offers {remaining} bytes \
                 from offset {offset}, but the ticket declares a {}-byte file ({expected} expected) \
                 — refusing before writing anything",
                file_ref.size
            )));
        }
        let total = file_ref.size;

        receive_into_part(
            &mut recv,
            &part_path,
            dest_dir,
            name,
            file_ref,
            offset,
            remaining,
            total,
            prehash.take(),
            &mut on_progress,
        )
        .await
    }
    .await;

    match streamed {
        Ok(final_path) => Ok(final_path),
        Err(e) => {
            // DESIGN §6.2: "partial kept — resume applies" on a connection loss. A stream I/O
            // break (`NetError::Io`) is the same class — the QUIC stream broke mid-copy, and the
            // bytes already on disk are still good. Everything else discards the partial: a peer
            // cancel, a hash mismatch, a refusal, a protocol inconsistency, and — since codex #6 —
            // a LOCAL filesystem failure (`LocalIo`: disk full, permission, rename), which is not
            // a resumable condition.
            let keep_partial = matches!(e, NetError::ConnectionLost(_) | NetError::Io(_));
            if !keep_partial {
                let _ = tokio::fs::remove_file(&part_path).await;
            }
            Err(e)
        }
    }
}

/// The state derived from an existing `<name>.part`, used by [`pull_file`]'s resume path.
enum PartialState {
    /// No partial exists — pull from offset 0.
    Absent,
    /// A partial of `len < size` bytes exists; re-hash it from byte 0 into `hasher` so the final
    /// hash covers the whole file, then request `offset = len`.
    Resumable { len: u64, hasher: Sha256 },
    /// The partial is already the full file (`len == size`) — re-hash it so the final-hash check
    /// covers the existing bytes, then request `offset = size` (0 remaining) and go straight to
    /// verify.
    Complete { hasher: Sha256 },
}

/// Read `<name>.part` (if present), hash its bytes from byte 0 into a fresh SHA-256 state, and
/// classify it. A partial larger than `size` is malformed — treat as `Absent` (the resume offset
/// would exceed size, and the server-side guard would refuse it anyway; better to restart clean
/// than to surface a confusing partial-length error).
fn compute_partial_state(part_path: &Path, size: u64) -> PartialState {
    use std::io::Read;
    let f = match std::fs::File::open(part_path) {
        Ok(f) => f,
        Err(_) => return PartialState::Absent,
    };
    let meta = match f.metadata() {
        Ok(m) => m,
        Err(_) => return PartialState::Absent,
    };
    let len = meta.len();
    if len == 0 || len > size {
        // Empty or oversized partial — restart from 0. Remove the malformed partial so the next
        // attempt doesn't re-discover it (the simple `requested_offset == 0` path).
        let _ = std::fs::remove_file(part_path);
        return PartialState::Absent;
    }
    // Hash the partial from byte 0 so the final hash covers the WHOLE file (the seam at engine.rs
    // ~line 160 in the M2 form). One pass; the same hasher feeds either the Resumable or Complete
    // branch.
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(f);
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => {
                let _ = std::fs::remove_file(part_path);
                return PartialState::Absent;
            }
        }
    }
    if len == size {
        // Full-size partial — skip the network read; `offset = size` with this hasher feeds the
        // final-hash check directly.
        PartialState::Complete { hasher }
    } else {
        PartialState::Resumable { len, hasher }
    }
}

/// Stream the response body into `part_path`, verify the hash, and rename into place. Errors are
/// returned to the caller ([`pull_file`] decides the partial's fate by class).
#[allow(clippy::too_many_arguments)]
async fn receive_into_part(
    recv: &mut (impl AsyncRead + Unpin),
    part_path: &Path,
    dest_dir: &Path,
    name: &str,
    file_ref: &FileRef,
    offset: u64,
    remaining: u64,
    total: u64,
    prehash: Option<Sha256>,
    on_progress: &mut impl FnMut(u64, u64),
) -> Result<PathBuf, NetError> {
    // Open the partial in the right mode: append if resuming (offset > 0), truncate if pulling
    // from 0. `offset > 0` with no `prehash` is a caller bug (the caller's `requested_offset`
    // path must supply its own prehash when it pre-built the partial); here we treat the missing
    // prehash case as "hash starts empty" — which would only happen on a misuse, and the final
    // hash check catches it.
    // Local filesystem failures are tagged `LocalIo`, distinct from a peer stream break (codex #6)
    // — the caller keeps a partial only for the latter.
    let local = |what: &str, e: std::io::Error| NetError::LocalIo(format!("{what}: {e}"));
    let mut out = if offset > 0 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(part_path)
            .await
            .map_err(|e| local("could not reopen the partial download to append", e))?
    } else {
        tokio::fs::File::create(part_path)
            .await
            .map_err(|e| local("could not create the partial download file", e))?
    };

    let mut hasher = prehash.unwrap_or_default();
    const CHUNK: usize = 256 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut done = offset;
    on_progress(done, total);
    let mut left = remaining;
    while left > 0 {
        let to_read = (left as usize).min(CHUNK);
        let n = recv.read(&mut buf[..to_read]).await?;
        if n == 0 {
            // Flush whatever we have so far BEFORE surfacing the loss — the partial must hold the
            // bytes we DID receive so a later redial can resume from its length (DESIGN §6.2).
            let _ = out.flush().await;
            return Err(NetError::ConnectionLost(
                "connection lost — transfer stopped before the file finished".into(),
            ));
        }
        out.write_all(&buf[..n])
            .await
            .map_err(|e| local("could not write to the partial download", e))?;
        hasher.update(&buf[..n]);
        done += n as u64;
        left -= n as u64;
        on_progress(done, total);
    }
    out.flush().await.map_err(|e| local("could not flush the partial download", e))?;
    drop(out); // close the handle before the rename (required on Windows)

    // The final hash covers the WHOLE file (the prehash from offset 0 + the streamed tail); a
    // mismatch means the sender's file changed between attempts — surface "file changed".
    let hash: [u8; 32] = hasher.finalize().into();
    if hash != file_ref.sha256 {
        // The caller (pull_file) deletes the partial on HashMismatch per the class split.
        return Err(NetError::HashMismatch);
    }

    let final_path = unique_destination(dest_dir, name);
    tokio::fs::rename(part_path, &final_path)
        .await
        .map_err(|e| local("could not move the verified download into place", e))?;
    Ok(final_path)
}

/// `name (2).ext`, `name (3).ext`, … — never overwrite an existing file (DESIGN §4).
fn unique_destination(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = path.extension().and_then(|s| s.to_str());
    for n in 2.. {
        let numbered = match ext {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        let candidate = dir.join(&numbered);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("the loop above only terminates by returning")
}

// --------------------------------------------------------------------------------------------
// Folder pull (DESIGN §4/§5). fetch_manifest is one bi-stream (stage-1 consent covers it);
// pull_folder is sequential per-file `file` ops (stage-2 consent interposes between them).
// --------------------------------------------------------------------------------------------

/// Fetch and verify a folder manifest over an already-open bi-directional stream (DESIGN §4).
/// One op: request `Op::Manifest`, read the `u64-LE total`, **refuse `total > 32 MiB` BEFORE
/// allocating** (mirror of `MAX_REQUEST_FRAME`), buffer fully, `decode_and_verify` (its caps
/// re-check), and **verify `sha256(bytes) == folder_ref.root_hash` BEFORE returning any entry to
/// the caller** (`sem_folderref_manifest_verified_before_use` — TOCTOU guard, chorus H4). Also
/// writes the verified bytes to `cache_dir` (the receiver-side `<...>/manifests/<nonce-
/// hex>.postcard`, DESIGN §7) for resume.
///
/// `cache_dir` is the directory under which `manifests/<nonce-hex>.postcard` is written. Pass the
/// destination root (or a Mascara home) — whichever the caller wants the cache to live under.
pub async fn fetch_manifest(
    mut send: impl AsyncWrite + Unpin,
    mut recv: impl AsyncRead + Unpin,
    nonce: Nonce,
    folder_ref: &FolderRef,
    cache_dir: &Path,
) -> Result<Manifest, NetError> {
    let req = Request { v: PROTOCOL_VERSION, nonce, op: Op::Manifest };
    let bytes = serde_json::to_vec(&req)
        .map_err(|e| NetError::Protocol(format!("could not encode manifest request: {e}")))?;
    send.write_u32_le(bytes.len() as u32).await?;
    send.write_all(&bytes).await?;
    send.shutdown().await?;

    let status = recv.read_u8().await?;
    if status != 0 {
        let elen = recv.read_u32_le().await? as usize;
        if elen > MAX_REQUEST_FRAME {
            return Err(NetError::Protocol(format!(
                "the sender's error message is too large ({elen} bytes, cap {MAX_REQUEST_FRAME} bytes)"
            )));
        }
        let mut ebuf = vec![0u8; elen];
        recv.read_exact(&mut ebuf).await?;
        return Err(NetError::Refused(String::from_utf8_lossy(&ebuf).into_owned()));
    }
    let total = recv.read_u64_le().await?;
    // chorus H4 / `sem_manifest_cap_enforced`: refuse over-cap BEFORE allocating the buffer. A
    // hostile sender's `total = u64::MAX` must not OOM the receiver.
    if total as usize > MAX_MANIFEST_FRAME {
        return Err(NetError::Protocol(format!(
            "the sender's manifest is {total} bytes — over the {} cap; refusing before allocation",
            MAX_MANIFEST_FRAME
        )));
    }
    let mut buf = vec![0u8; total as usize];
    recv.read_exact(&mut buf).await?;

    // Cap + decode + verify in one call. `decode_and_verify` hashes the supplied bytes (not a
    // re-encoding) against `folder_ref.root_hash`, so a byte-form that does not match the
    // commitment is refused even if it re-parses to a struct that "looks right" — the TOCTOU guard.
    let outcome = decode_and_verify_manifest(&buf, &folder_ref.root_hash)?;
    let manifest = outcome.into_manifest();

    // Cache the verified bytes (DESIGN §7 `manifests/`; the M5 GUI's offline white/greyed view is
    // the intended reader — nothing reads it at M3). FQ3's "stale folder resume fails closed" is
    // delivered by something stronger than a cache diff: the ticket itself pins `root_hash`, so
    // EVERY fetch (including a resume's re-fetch, just above) verifies against the immutable
    // sealed commitment — a drifted manifest cannot pass, cached copy or no cached copy.
    let cache_path = cache_dir.join("manifests").join(format!("{}.postcard", nonce.to_hex()));
    if let Some(dir) = cache_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    atomic_write(&cache_path, &buf)?;

    Ok(manifest)
}

/// Sequential per-file pull of every entry in `manifest` (DESIGN §4). Each entry is one `file`
/// op on its own bi-stream — the caller (`dialer::pull_folder`) opens one bi-stream per entry and
/// hands it to [`pull_entry`] with a per-entry `FileRef` built from the [`ManifestEntry`]. Entries
/// write only beneath `dest_root`, creating intermediate dirs; the receiver-side path guard
/// ([`safe_rel_path`]) fires per entry BEFORE any filesystem op (`sem_folder_paths_guarded`).
///
/// `open_stream` is called once per entry and returns the `(send, recv)` pair for that op — this
/// keeps the engine iroh-free (the dialer owns `conn.open_bi()`). `on_file_progress(rel_path,
/// done, total)` fires per chunk.
///
/// `on_entry_done(entry, landed_path)` fires as each entry finishes and hash-verifies, BEFORE the
/// next entry starts (codex #8). A folder pull can fail partway; a caller that only reacted to the
/// final `Ok` would never learn about the entries that DID complete — leaving their history
/// records stuck "in progress" (and, per MR-7, still holding an origin) despite finished files on
/// disk. The callback is the per-entry completion signal.
pub async fn pull_folder<S, Fut, P, D>(
    manifest: &Manifest,
    nonce: Nonce,
    dest_root: &Path,
    mut open_stream: S,
    mut on_file_progress: P,
    mut on_entry_done: D,
) -> Result<Vec<PathBuf>, NetError>
where
    S: FnMut(&ManifestEntry) -> Fut,
    Fut: std::future::Future<Output = Result<(Box<dyn AsyncWrite + Unpin + Send>, Box<dyn AsyncRead + Unpin + Send>), NetError>>,
    P: FnMut(&str, u64, u64),
    D: FnMut(&ManifestEntry, &Path),
{
    let mut completed = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        // Path guard BEFORE any filesystem op per entry (chorus H5). The authenticated root_hash
        // commits to bytes, not path safety — a malicious sender can notarize `../../etc/passwd`.
        safe_rel_path(&entry.rel_path)?;
        // Resolve (and create) the entry's destination directory and prove it stays under the
        // chosen root BEFORE a stream is opened (codex #1) — a symlinked component in the
        // destination is invisible to the lexical guard above, and there is no point dialing for
        // bytes we would refuse to write.
        let entry_dest = prepare_entry_dest(dest_root, &entry.rel_path)?;
        let entry_ref = FileRef {
            name: entry.rel_path.clone(),
            size: entry.size,
            sha256: entry.sha256,
            md5: entry.md5,
            mime: None,
        };
        let (send, recv) = open_stream(entry).await?;
        let final_path = pull_entry(
            send,
            recv,
            nonce,
            &entry_ref,
            &entry_dest,
            |done, total| on_file_progress(&entry.rel_path, done, total),
        )
        .await?;
        // Signal completion BEFORE the next entry starts, so a later failure cannot erase the
        // record of this one having finished (codex #8).
        on_entry_done(entry, &final_path);
        completed.push(final_path);
    }
    Ok(completed)
}

/// Pull one folder entry into `dest_root/<entry.rel_path>` (the rel-path is already validated by
/// [`safe_rel_path`] in [`pull_folder`]). Internal companion to [`pull_file`] that uses the entry's
/// full rel-path as the destination (not the single-file safe_filename form) — the guard already
/// ran in `pull_folder`. Same resume, hash-verify, and `.part`-retention-by-class discipline as
/// `pull_file`.
fn prepare_entry_dest(dest_root: &Path, rel_path: &str) -> Result<PathBuf, NetError> {
    // The entry's rel_path is the full sub-path (e.g. "subs/en.srt"); join it beneath dest_root
    // for the final destination. The rel-path was already verified all-Normal by safe_rel_path.
    let entry_dest = dest_root.join(rel_path);
    if let Some(parent) = entry_dest.parent() {
        std::fs::create_dir_all(parent)?;
        // codex #1: `safe_rel_path` is LEXICAL — it cannot see that a component already on disk is
        // a symlink out of the tree (`<dest>/sub -> /etc`), which `create_dir_all` happily follows
        // and the `.part` write would then land outside the chosen root. Resolve the created
        // parent and require it to stay under the resolved root before any file is opened.
        let canon_root = std::fs::canonicalize(dest_root)
            .map_err(|e| NetError::LocalIo(format!("could not resolve the destination: {e}")))?;
        let canon_parent = std::fs::canonicalize(parent)
            .map_err(|e| NetError::LocalIo(format!("could not resolve the destination subdir: {e}")))?;
        if !canon_parent.starts_with(&canon_root) {
            return Err(NetError::Protocol(format!(
                "refusing the manifest path {rel_path:?}: it resolves outside the chosen directory \
                 (a symlinked component in the destination) — a received folder entry must land \
                 inside it, never escape"
            )));
        }
        // The entry itself must not be an existing symlink either: writing through it would
        // clobber whatever it points at. `symlink_metadata` does not follow the link.
        if let Ok(meta) = std::fs::symlink_metadata(&entry_dest) {
            if meta.file_type().is_symlink() {
                return Err(NetError::Protocol(format!(
                    "refusing the manifest path {rel_path:?}: a symlink already exists at that \
                     destination — refusing to write through it"
                )));
            }
        }
    }
    Ok(entry_dest)
}

/// Pull one folder entry into `entry_dest` (already validated + created by
/// [`prepare_entry_dest`], its rel-path already lexically guarded by [`safe_rel_path`]). Internal
/// companion to [`pull_file`]: same resume, hash-verify, and `.part`-retention-by-class discipline.
async fn pull_entry(
    send: impl AsyncWrite + Unpin,
    recv: impl AsyncRead + Unpin,
    nonce: Nonce,
    entry_ref: &FileRef,
    entry_dest: &Path,
    on_progress: impl FnMut(u64, u64),
) -> Result<PathBuf, NetError> {
    // pull_entry shares pull_file's wire + resume + verify logic; delegate to it with the entry's
    // leaf filename and the entry's destination PARENT as the dest_dir (so the `.part` lands in the
    // right subdir), then move the renamed file into its final rel-path.
    let leaf = Path::new(&entry_ref.name)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| NetError::Protocol(format!("entry has no leaf filename: {:?}", entry_ref.name)))?;
    let mut leaf_ref = entry_ref.clone();
    leaf_ref.name = leaf.to_string();
    let parent = entry_dest.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    // Wire path = the manifest rel-path (the listener matches manifest ENTRIES); local name = the
    // leaf (landing beneath the entry's parent dir).
    let pulled =
        pull_file_inner(send, recv, nonce, &entry_ref.name, &leaf_ref, 0, &parent, on_progress).await?;
    // pull_file renamed the leaf into the parent; if the plain-leaf name differs from the entry's
    // full destination (the subdir case), move it the rest of the way. On a collision pull_file
    // produced a `leaf (N).ext` and we leave it where it is (still beneath dest_root, just with a
    // disambiguating suffix) — correct, just rarer.
    let plain = parent.join(leaf);
    if pulled != entry_dest && plain == pulled && plain.exists() {
        tokio::fs::rename(&plain, entry_dest)
            .await
            .map_err(|e| NetError::LocalIo(format!("could not place the folder entry: {e}")))?;
        Ok(entry_dest.to_path_buf())
    } else {
        Ok(pulled)
    }
}

/// Delete the `.part` for a single-file pull after a peer-initiated cancel
/// (`sem_partials_deleted_on_cancel`, DESIGN §4 delete-on-cancel). The engine itself KEEPS the
/// partial on a stream break (`pull_file`'s retention-by-class — it cannot see QUIC close codes),
/// so the dialer calls this once `classify_io_failure` has resolved the break to
/// [`NetError::Cancelled`]. Idempotent; an unsafe declared name means nothing was ever written.
pub(crate) fn remove_partial_on_cancel(dest_dir: &Path, declared_name: &str) {
    if let Ok(name) = safe_filename(declared_name) {
        let _ = std::fs::remove_file(dest_dir.join(format!("{name}.part")));
    }
}

/// The folder form of [`remove_partial_on_cancel`]: delete every entry's `.part` beneath
/// `dest_root` after a peer-initiated cancel. Only guard-passing rel-paths are touched (an unsafe
/// entry never wrote anything); completed files are left alone — cancel discards in-flight
/// partials, not verified results.
pub(crate) fn remove_entry_partials_on_cancel(dest_root: &Path, manifest: &Manifest) {
    for entry in &manifest.entries {
        if safe_rel_path(&entry.rel_path).is_ok() {
            let _ = std::fs::remove_file(dest_root.join(format!("{}.part", entry.rel_path)));
        }
    }
}

/// Atomic tmp+rename write, mirror of `listener::atomic_write` (kept local so the engine stays
/// independent of the listener module's private helper).
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), NetError> {
    use rand::RngCore;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("data");
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(".{stem}.{}.tmp", hex::encode(suffix)));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_ref_for(content: &[u8], name: &str) -> FileRef {
        FileRef {
            name: name.into(),
            size: content.len() as u64,
            sha256: Sha256::digest(content).into(),
            md5: [0u8; 16],
            mime: None,
        }
    }

    /// A minimal hand-rolled server counterpart writing the DESIGN §4 response frame directly —
    /// exercises `pull_file` in isolation from `listener::handle_request` (that combination is
    /// covered end-to-end in `tests/xfer.rs`).
    async fn respond_ok(mut send: impl AsyncWrite + Unpin, content: &[u8]) {
        send.write_u8(0).await.unwrap();
        send.write_u64_le(content.len() as u64).await.unwrap();
        send.write_all(content).await.unwrap();
        send.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn happy_path_streams_and_verifies() {
        let content = b"hello mascara".to_vec();
        let file_ref = file_ref_for(&content, "hello.txt");
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        let content2 = content.clone();
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            // Drain the request frame so the client's writes don't block.
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            respond_ok(srv_w, &content2).await;
        });

        let dest = tempfile::tempdir().unwrap();
        let mut progress_calls = Vec::new();
        let path = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |done, total| {
            progress_calls.push((done, total));
        })
        .await
        .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), content);
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "hello.txt");
        assert!(!progress_calls.is_empty());
        assert_eq!(*progress_calls.last().unwrap(), (content.len() as u64, content.len() as u64));
    }

    #[tokio::test]
    async fn hash_mismatch_removes_partial() {
        let content = b"actual bytes".to_vec();
        let mut file_ref = file_ref_for(&content, "x.bin");
        file_ref.sha256 = [0xEE; 32]; // wrong on purpose
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            respond_ok(srv_w, &content).await;
        });

        let dest = tempfile::tempdir().unwrap();
        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::HashMismatch));
        assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none(), "the .part must be removed");
    }

    #[tokio::test]
    async fn refusal_response_surfaces_as_refused_error() {
        let file_ref = file_ref_for(b"x", "x.bin");
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            let msg = b"this ticket is unknown, revoked, or expired";
            srv_w.write_u8(1).await.unwrap();
            srv_w.write_u32_le(msg.len() as u32).await.unwrap();
            srv_w.write_all(msg).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Refused(msg) if msg.contains("unknown, revoked")));
    }

    #[test]
    fn safe_filename_accepts_plain_names() {
        for ok in ["hello.txt", "Akira_1988.mkv", "no-ext", "a (2).txt", "úñïçödé.dat"] {
            assert_eq!(safe_filename(ok).unwrap(), ok, "{ok:?} should be accepted");
        }
    }

    #[test]
    fn safe_filename_rejects_traversal_and_escapes() {
        for bad in [
            "", ".", "..", "../escape.txt", "a/b.txt", "sub\\b.txt", "/etc/passwd", "C:evil",
            // codex #2: ADS reference and Windows-stripped trailing dot/space.
            "report:payload", "evil.txt.", "evil.txt ",
        ] {
            let err = safe_filename(bad).unwrap_err();
            assert!(matches!(err, NetError::Protocol(_)), "{bad:?} should be refused, got {err:?}");
        }
    }

    /// `sem_folder_paths_guarded` — the manifest-entry form of the path guard. Subdir paths are
    /// accepted; absolute, `..`, `\`, drive-letter, and Windows-reserved forms are refused.
    #[test]
    fn safe_rel_path_accepts_subdir_paths() {
        for ok in ["hello.txt", "subs/en.srt", "a/b/c/d.bin", "Akira (1988).mkv", "úñïçödé.dat"] {
            assert_eq!(safe_rel_path(ok).unwrap(), ok, "{ok:?} should be accepted");
        }
    }

    #[test]
    fn safe_rel_path_rejects_traversal_and_escapes() {
        let bad = [
            "",
            "..",
            "../etc/passwd",
            "a/../b",
            "a/./b",
            "/etc/passwd",
            "a\\b",
            "C:evil",
            // codex #2: NTFS alternate-data-stream refs and Windows-stripped trailing dots/spaces.
            "report:payload",
            "sub/report:hidden",
            "evil.txt.",
            "evil.txt ",
            "sub./x",
            "CON",
            "con.txt",
            "PRN.bin",
            "AUX",
            "NUL",
            "COM1",
            "com9.srt",
            "LPT1",
            "lpt5",
            "sub/COM3",
        ];
        for b in bad {
            let err = safe_rel_path(b).unwrap_err();
            assert!(matches!(err, NetError::Protocol(_)), "{b:?} should be refused, got {err:?}");
        }
    }

    #[tokio::test]
    async fn traversal_filename_refused_before_any_write() {
        // The guard fires before the stream is touched, so a never-answering server is fine.
        let file_ref = file_ref_for(b"x", "../escape.txt");
        let (_srv, cli) = tokio::io::duplex(64 * 1024);
        let (cli_r, cli_w) = tokio::io::split(cli);
        let dest = tempfile::tempdir().unwrap();
        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Protocol(msg) if msg.contains("escape")));
        assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none(), "nothing may be written");
    }

    #[tokio::test]
    async fn oversize_error_frame_refused_before_allocation() {
        let file_ref = file_ref_for(b"x", "x.bin");
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            // status=1 (refused) then a dishonest 4 GiB error-frame length, but no such bytes.
            srv_w.write_u8(1).await.unwrap();
            srv_w.write_u32_le(u32::MAX).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Protocol(msg) if msg.contains("too large")));
    }

    /// **M3 behavior reversal** (DESIGN §6.2: "partial kept — resume applies"): a connection loss
    /// mid-stream now KEEPS the `.part` so a later redial can resume from its length. M2 deleted
    /// the partial on every error exit; this test was renamed from `connection_lost_removes_partial`.
    #[tokio::test]
    async fn connection_lost_keeps_partial_for_resume() {
        // Server promises 1000 bytes, sends 3, then drops — the `.part` must SURVIVE for resume.
        let mut file_ref = file_ref_for(b"unused", "drop.bin");
        file_ref.size = 1000;
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            srv_w.write_u8(0).await.unwrap();
            srv_w.write_u64_le(1000).await.unwrap();
            srv_w.write_all(b"abc").await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::ConnectionLost(_)));
        let part = dest.path().join("drop.bin.part");
        assert!(part.exists(), "the .part must be KEPT for resume (DESIGN §6.2)");
        assert_eq!(std::fs::read(&part).unwrap(), b"abc", "the partial bytes must be present");
    }

    /// `sem_resume_offset_guarded` — a pre-existing `.part` is re-hashed from byte 0 and the pull
    /// resumes at its length; the final hash covers the WHOLE file.
    #[tokio::test]
    async fn resume_picks_up_partial_and_covers_whole_file() {
        // Full content = "0123456789"; a partial "0123" is already on disk.
        let full = b"0123456789".to_vec();
        let file_ref = file_ref_for(&full, "resumable.bin");
        let dest = tempfile::tempdir().unwrap();
        // Seed the partial with the first 4 bytes.
        std::fs::write(dest.path().join("resumable.bin.part"), &full[..4]).unwrap();

        // Server should receive offset=4 and stream the remaining 6 bytes.
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        let tail = full[4..].to_vec();
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            // Confirm the request actually asked for offset=4 (resume detected the partial).
            let req: Request = serde_json::from_slice(&buf).unwrap();
            match req.op {
                Op::File { offset, .. } => assert_eq!(offset, 4, "must resume at the partial length"),
                _ => panic!("expected a File op"),
            }
            respond_ok(srv_w, &tail).await;
        });

        let path = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), full, "the resumed file must equal the whole");
        // The .part is consumed (renamed into place).
        assert!(!dest.path().join("resumable.bin.part").exists());
    }

    /// `offset == size` — a complete partial skips the network read and verifies straight away.
    #[tokio::test]
    async fn complete_partial_skips_network_and_verifies() {
        let full = b"complete-file-bytes".to_vec();
        let file_ref = file_ref_for(&full, "complete.bin");
        let dest = tempfile::tempdir().unwrap();
        // Seed the partial with the WHOLE file already.
        std::fs::write(dest.path().join("complete.bin.part"), &full).unwrap();

        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        let full_len = full.len() as u64;
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            // Confirm the request asked for offset == size (the engine detected completeness and
            // asked for 0 remaining bytes).
            let req: Request = serde_json::from_slice(&buf).unwrap();
            match req.op {
                Op::File { offset, .. } => {
                    assert_eq!(offset, full_len, "must request offset == size");
                }
                _ => panic!("expected a File op"),
            }
            // Server responds with 0 remaining bytes.
            srv_w.write_u8(0).await.unwrap();
            srv_w.write_u64_le(0).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let path = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), full);
    }

    /// A tampered partial (bytes don't match what the sender originally produced) is detected at
    /// the final hash and deleted; the "file changed on the sender's side — restart" semantics
    /// apply (here the partial itself was tampered, same outcome from the hash check's POV).
    #[tokio::test]
    async fn tampered_partial_detected_at_final_hash() {
        let full = b"0123456789".to_vec();
        let file_ref = file_ref_for(&full, "tampered.bin");
        let dest = tempfile::tempdir().unwrap();
        // Seed the partial with 4 WRONG bytes — the resume will hash them and request offset=4,
        // but the final hash (wrong-prefix + real-tail) won't match the ticket's sha256.
        std::fs::write(dest.path().join("tampered.bin.part"), b"XXXX").unwrap();

        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        let tail = full[4..].to_vec();
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            respond_ok(srv_w, &tail).await;
        });

        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::HashMismatch));
        assert!(
            !dest.path().join("tampered.bin.part").exists(),
            "the tampered partial must be deleted on hash mismatch"
        );
    }

    /// A hostile server claiming `remaining = u64::MAX` is refused against the ticket's DECLARED
    /// size before a single byte is written (codex #4) — the strengthened form of the old
    /// `checked_add` overflow guard, which caught only the arithmetic and would still have let a
    /// merely-huge (non-overflowing) `remaining` stream until the disk filled.
    #[tokio::test]
    async fn hostile_remaining_overflow_refused() {
        let file_ref = file_ref_for(b"x", "of.bin");
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            srv_w.write_u8(0).await.unwrap();
            // Dishonest: claim u64::MAX remaining against whatever offset was requested.
            srv_w.write_u64_le(u64::MAX).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        // Pass a nonzero offset — the historical overflow shape (`offset + u64::MAX`).
        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 1, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        match err {
            NetError::Protocol(msg) => {
                assert!(msg.contains("inconsistent with the ticket"), "got: {msg}")
            }
            other => panic!("expected a Protocol inconsistency error, got: {other}"),
        }
        assert!(
            std::fs::read_dir(dest.path()).unwrap().next().is_none(),
            "nothing may be written for an inconsistent response"
        );
    }

    /// codex #4, the non-overflowing half: a merely-HUGE `remaining` (no u64 wrap) is refused just
    /// as hard — the old `checked_add` guard would have accepted this and streamed to disk-full.
    #[tokio::test]
    async fn hostile_oversized_remaining_refused_before_writing() {
        let file_ref = file_ref_for(b"small", "s.bin");
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            srv_w.write_u8(0).await.unwrap();
            srv_w.write_u64_le(64 * 1024 * 1024 * 1024).await.unwrap(); // 64 GiB, no overflow
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(
            matches!(&err, NetError::Protocol(msg) if msg.contains("inconsistent with the ticket")),
            "got: {err}"
        );
        assert!(
            std::fs::read_dir(dest.path()).unwrap().next().is_none(),
            "a 64 GiB claim against a 5-byte ticket must write nothing"
        );
    }

    /// codex #6: a pre-existing `.part` must NOT survive a refusal — the refusal path previously
    /// returned before the retention match, stranding the partial forever.
    #[tokio::test]
    async fn refusal_removes_a_pre_existing_partial() {
        let content = b"resumable content here".to_vec();
        let file_ref = file_ref_for(&content, "r.bin");
        let dest = tempfile::tempdir().unwrap();
        // Seed a partial as an interrupted attempt would have left it.
        std::fs::write(dest.path().join("r.bin.part"), &content[..5]).unwrap();

        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            let msg = b"this ticket is unknown, revoked, or expired";
            srv_w.write_u8(1).await.unwrap();
            srv_w.write_u32_le(msg.len() as u32).await.unwrap();
            srv_w.write_all(msg).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let err = pull_file(cli_w, cli_r, Nonce::mint(), &file_ref, 0, dest.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Refused(_)), "got: {err}");
        assert!(
            !dest.path().join("r.bin.part").exists(),
            "a refusal must discard the partial — the ticket is dead, it can never be resumed"
        );
    }

    /// `fetch_manifest` — manifest fully buffered + verified before any entry returned. A tampered
    /// byte breaks the hash and is refused by `decode_and_verify` (the root_hash gate).
    #[tokio::test]
    async fn fetch_manifest_buffers_and_verifies() {
        use mascara_core::{manifest::encode, Manifest as M, ManifestEntry as ME};
        let entries = vec![
            ME { rel_path: "a.bin".into(), size: 4, sha256: [7; 32], md5: [0x11; 16], mode: 0o644 },
            ME { rel_path: "sub/b.bin".into(), size: 8, sha256: [8; 32], md5: [0x22; 16], mode: 0o600 },
        ];
        let manifest = M { v: mascara_core::MANIFEST_VERSION, entries };
        let bytes = encode(&manifest).unwrap();
        let root_hash: [u8; 32] = Sha256::digest(&bytes).into();
        let folder_ref = FolderRef { name: "x".into(), root_hash };

        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        let bytes2 = bytes.clone();
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            srv_w.write_u8(0).await.unwrap();
            srv_w.write_u64_le(bytes2.len() as u64).await.unwrap();
            srv_w.write_all(&bytes2).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        let got = fetch_manifest(cli_w, cli_r, Nonce::mint(), &folder_ref, dest.path()).await.unwrap();
        assert_eq!(got, manifest);
        // The verified bytes were cached for resume.
        let cache = dest.path().join("manifests");
        assert!(cache.exists(), "the manifests/ cache dir must be created");
    }

    /// `fetch_manifest` refuses an oversized total BEFORE allocating (hostile `total = u64::MAX`).
    #[tokio::test]
    async fn fetch_manifest_refuses_oversized_total_before_allocation() {
        let folder_ref = FolderRef { name: "x".into(), root_hash: [0; 32] };
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            // Dishonest: claim a total over the 32 MiB cap, send no such bytes.
            srv_w.write_u8(0).await.unwrap();
            srv_w.write_u64_le((MAX_MANIFEST_FRAME as u64) + 1).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        let err = fetch_manifest(cli_w, cli_r, Nonce::mint(), &folder_ref, dest.path())
            .await
            .unwrap_err();
        match err {
            NetError::Protocol(msg) => {
                assert!(msg.contains("over the") && msg.contains("cap"), "got: {msg}")
            }
            other => panic!("expected a Protocol cap refusal, got: {other}"),
        }
    }

    /// `fetch_manifest` refuses tampered bytes (hash check fails against the ticket's root_hash).
    #[tokio::test]
    async fn fetch_manifest_refuses_tampered_bytes() {
        use mascara_core::{manifest::encode, Manifest as M, ManifestEntry as ME};
        let entry = ME { rel_path: "a.bin".into(), size: 4, sha256: [7; 32], md5: [0x11; 16], mode: 0o644 };
        let manifest = M { v: mascara_core::MANIFEST_VERSION, entries: vec![entry] };
        let mut bytes = encode(&manifest).unwrap();
        let root_hash: [u8; 32] = Sha256::digest(&bytes).into();
        // Flip one byte in the middle of the body. The byte we pick is inside the entry's sha256
        // field — flipping 0x07 to 0x08 (a single-bit flip) keeps the postcard length-prefixing
        // intact, so the bytes still decode but the root_hash check refuses them. (Flipping byte 0
        // would change the version; flipping the last byte would change the trailing mode varint
        // length and break decoding — neither shows the root_hash gate the way a mid-body flip does.)
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let folder_ref = FolderRef { name: "x".into(), root_hash };

        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let (cli_r, cli_w) = tokio::io::split(cli);
        let bytes2 = bytes.clone();
        tokio::spawn(async move {
            let mut srv_r = srv_r;
            let mut srv_w = srv_w;
            let len = srv_r.read_u32_le().await.unwrap();
            let mut buf = vec![0u8; len as usize];
            srv_r.read_exact(&mut buf).await.unwrap();
            srv_w.write_u8(0).await.unwrap();
            srv_w.write_u64_le(bytes2.len() as u64).await.unwrap();
            srv_w.write_all(&bytes2).await.unwrap();
            srv_w.shutdown().await.unwrap();
        });

        let dest = tempfile::tempdir().unwrap();
        let err = fetch_manifest(cli_w, cli_r, Nonce::mint(), &folder_ref, dest.path())
            .await
            .unwrap_err();
        // A mid-body byte flip either trips the hash check directly (root_hash mismatch — the
        // byte-form changed) or breaks decoding; both are reasoned refusals. The hash check is the
        // property we most want to show, so assert that's what fired.
        match err {
            NetError::Core(mascara_core::CoreError::Manifest(msg)) => {
                assert!(msg.contains("root_hash mismatch"), "got: {msg}")
            }
            other => panic!("expected a Core::Manifest root_hash-mismatch refusal, got: {other}"),
        }
    }

    #[test]
    fn unique_destination_suffixes_on_collision() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"1").unwrap();
        let first = unique_destination(dir.path(), "a.txt");
        assert_eq!(first.file_name().unwrap().to_str().unwrap(), "a (2).txt");
        std::fs::write(&first, b"2").unwrap();
        let second = unique_destination(dir.path(), "a.txt");
        assert_eq!(second.file_name().unwrap().to_str().unwrap(), "a (3).txt");
    }

    #[test]
    fn unique_destination_is_the_plain_name_when_free() {
        let dir = tempfile::tempdir().unwrap();
        let path = unique_destination(dir.path(), "fresh.bin");
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "fresh.bin");
    }

    #[test]
    fn windows_reserved_detection() {
        // Reserved in any case and with/without extension.
        for ok in ["CON", "con", "Con.txt", "PRN.bin", "COM1", "com9", "LPT5", "lpt1.out"] {
            assert!(is_windows_reserved_name(ok), "{ok:?} should be reserved");
        }
        // Not reserved.
        for ok in ["CONsole", "PRName", "COM10", "COM0", "LPTO", "regular.txt", "AUXIN"] {
            assert!(!is_windows_reserved_name(ok), "{ok:?} should NOT be reserved");
        }
    }
}
