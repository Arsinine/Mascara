//! Single-file pull orchestration — the client half of `/mascara/xfer/1` (DESIGN §4/§6). Mining
//! map: the quarry's `download_file_inner` progress/cancel shape → here, with the full-file
//! re-read hash replaced by an incremental one (D-resume keeps the offset seam for M3; M2 always
//! pulls from 0).
//!
//! Written against generic `AsyncRead+AsyncWrite` so the exact same logic runs over
//! `tokio::io::duplex` in tests and a real iroh `RecvStream`/`SendStream` in production — the
//! iroh-specific glue (opening the bi-stream, translating a QUIC close code) lives in `dialer.rs`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use mascara_core::{FileRef, Nonce};

use crate::error::NetError;
use crate::listener::{MAX_REQUEST_FRAME, Op, Request};

/// The protocol version this milestone speaks (DESIGN §4).
pub const PROTOCOL_VERSION: u8 = 1;

/// A ticket's declared filename is **sender-controlled** — it must name one file *inside* the
/// chosen destination, never escape it. Accept only a single plain filename component; reject
/// empty, `.`/`..`, path separators (either slash — a `\` is a legal char on Unix but a separator
/// on the sender's Windows box), and absolute/rooted/drive/UNC forms — **before** any filesystem
/// operation. This is the single-file form of the chorus H5 path guard; the folder-manifest form
/// is M3's `sem_folder_paths_guarded`. Returns the safe name on success.
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
    let b = name.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return refuse("a Windows drive-letter path");
    }
    // Catch any remaining rooted/UNC forms: the name must resolve to exactly one *normal* path
    // component equal to the whole string.
    let mut comps = Path::new(name).components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(only)), None) if only.to_str() == Some(name) => Ok(name),
        _ => refuse("not a single plain filename component"),
    }
}

/// Pull one file over an already-open bi-directional stream: send the request, stream the
/// response into `<dest_dir>/<name>.part` with incremental SHA-256, verify the final hash
/// against `file_ref.sha256` **before** renaming into place — the hash gate is what makes the
/// file "available" (`sem_fileref_hash_verified_before_available`); a mismatch discards the
/// partial. A name collision on the final rename gets a numeric suffix (`name (2).ext`) — never
/// an overwrite. `on_progress(done, total)` fires after every chunk (no UI coupling).
pub async fn pull_file(
    mut send: impl AsyncWrite + Unpin,
    mut recv: impl AsyncRead + Unpin,
    nonce: Nonce,
    file_ref: &FileRef,
    offset: u64,
    dest_dir: &Path,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<PathBuf, NetError> {
    // Guard the sender-controlled name BEFORE touching the stream or the filesystem (chorus H5).
    let name = safe_filename(&file_ref.name)?;

    let req = Request { v: PROTOCOL_VERSION, nonce, op: Op::File { path: file_ref.name.clone(), offset } };
    let bytes = serde_json::to_vec(&req)
        .map_err(|e| NetError::Protocol(format!("could not encode request: {e}")))?;
    send.write_u32_le(bytes.len() as u32).await?;
    send.write_all(&bytes).await?;
    send.shutdown().await?;

    let status = recv.read_u8().await?;
    if status != 0 {
        // The error frame is sender-controlled — cap it before allocating, the client-side mirror
        // of the listener's `MAX_REQUEST_FRAME` gate, so a hostile peer can't provoke a 4 GiB
        // allocation with an oversized length prefix.
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
    let total = offset + remaining;

    std::fs::create_dir_all(dest_dir)?;
    let part_path = dest_dir.join(format!("{name}.part"));

    // Any error after the `.part` exists must not leave a partial behind (DESIGN §4 delete-on-
    // cancel / unrecoverable-failure). Stream in an inner helper; remove the `.part` on every
    // error exit — a successful rename consumes it, so the remove is a no-op on the Ok path.
    match receive_into_part(&mut recv, &part_path, dest_dir, name, file_ref, offset, remaining, total, &mut on_progress)
        .await
    {
        Ok(final_path) => Ok(final_path),
        Err(e) => {
            let _ = tokio::fs::remove_file(&part_path).await;
            Err(e)
        }
    }
}

/// Stream the response body into `part_path`, verify the hash, and rename into place. Every error
/// return leaves the `.part` for the caller to remove (the file handle is closed as this returns).
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
    on_progress: &mut impl FnMut(u64, u64),
) -> Result<PathBuf, NetError> {
    let mut out = tokio::fs::File::create(part_path).await?;

    let mut hasher = Sha256::new();
    const CHUNK: usize = 256 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut done = offset;
    on_progress(done, total);
    let mut left = remaining;
    while left > 0 {
        let to_read = (left as usize).min(CHUNK);
        let n = recv.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(NetError::ConnectionLost(
                "connection lost — transfer stopped before the file finished".into(),
            ));
        }
        out.write_all(&buf[..n]).await?;
        hasher.update(&buf[..n]);
        done += n as u64;
        left -= n as u64;
        on_progress(done, total);
    }
    out.flush().await?;
    drop(out); // close the handle before the rename (required on Windows)

    // NOTE (D-resume, M3 seam): at M2, `offset` is always 0, so the incremental hash above
    // covers the whole file end-to-end. A future resumed pull must pre-hash the partial's
    // existing bytes into an equivalent running `Sha256` before this function streams the tail.
    let hash: [u8; 32] = hasher.finalize().into();
    if hash != file_ref.sha256 {
        return Err(NetError::HashMismatch);
    }

    let final_path = unique_destination(dest_dir, name);
    tokio::fs::rename(part_path, &final_path).await?;
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
        for bad in ["", ".", "..", "../escape.txt", "a/b.txt", "sub\\b.txt", "/etc/passwd", "C:evil"] {
            let err = safe_filename(bad).unwrap_err();
            assert!(matches!(err, NetError::Protocol(_)), "{bad:?} should be refused, got {err:?}");
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

    #[tokio::test]
    async fn connection_lost_removes_partial() {
        // Server promises 1000 bytes, sends 3, then drops — the `.part` must not survive.
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
        assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none(), "the .part must be removed");
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
}
