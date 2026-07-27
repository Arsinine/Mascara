//! Suite XFER [M2] (TEST_PLAN.md §2) — the full request/response round trip over
//! `tokio::io::duplex` (L1, no QUIC — the quarry's proven technique), wiring
//! `mascara_net::listener::handle_request` (server) against `mascara_net::engine::pull_file`
//! (client) together. Real-iroh scenarios (the drain race, cancel close-code distinction) live
//! in `mascara-net`'s own `#[cfg(test)]` modules / `mascara-it` — see those for why.

use chrono::{Duration as ChronoDuration, Utc};
use mascara_core::{FileRef, Grant, IssuedRecord, IssuedTickets, Nonce};
use mascara_net::engine::pull_file;
use mascara_net::listener::{handle_request, OfferPayload, OfferRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REMOTE: [u8; 32] = [7u8; 32];

fn file_ref(content: &[u8], name: &str) -> FileRef {
    use sha2::{Digest, Sha256};
    FileRef { name: name.into(), size: content.len() as u64, sha256: Sha256::digest(content).into(), md5: [0u8; 16], mime: None }
}

fn issued(nonce: Nonce, remote: [u8; 32], expires_at: Option<chrono::DateTime<Utc>>) -> IssuedTickets {
    let mut t = IssuedTickets::default();
    t.issue(IssuedRecord::new(nonce, Some("f".into()), Utc::now(), expires_at, remote)).unwrap();
    t
}

#[tokio::test]
async fn happy_path_streams_and_verifies() {
    let content = b"the whole point of a courier".to_vec();
    let fr = file_ref(&content, "payload.bin");
    let nonce = Nonce::mint();
    let tickets = issued(nonce, REMOTE, None);
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path: write_temp(&content), file_ref: fr.clone() }, grant: Grant::Download };

    let (srv, cli) = tokio::io::duplex(64 * 1024);
    let (srv_r, srv_w) = tokio::io::split(srv);
    let (cli_r, cli_w) = tokio::io::split(cli);
    let offer2 = offer.clone();
    tokio::spawn(async move {
        let lookup = move |n: &Nonce| if n == &offer2.nonce { Some(offer2.clone()) } else { None };
        let _ = handle_request(srv_w, srv_r, REMOTE, &tickets, lookup, Utc::now()).await;
    });

    let dest = tempfile::tempdir().unwrap();
    let path = pull_file(cli_w, cli_r, nonce, &fr, 0, dest.path(), |_, _| {}).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), content);
}

#[tokio::test]
async fn revoked_nonce_refused() {
    let content = b"secret".to_vec();
    let fr = file_ref(&content, "s.bin");
    let nonce = Nonce::mint();
    let mut tickets = issued(nonce, REMOTE, None);
    tickets.revoke(&nonce).unwrap();
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path: write_temp(&content), file_ref: fr.clone() }, grant: Grant::Download };

    let err = run_refused(tickets, REMOTE, Some(offer), fr, nonce).await;
    assert!(err.contains("unknown, revoked, or expired"), "got: {err}");
}

#[tokio::test]
async fn unknown_nonce_refused() {
    let content = b"secret".to_vec();
    let fr = file_ref(&content, "s.bin");
    let nonce = Nonce::mint();
    let tickets = IssuedTickets::default(); // nothing issued at all

    let err = run_refused(tickets, REMOTE, None, fr, nonce).await;
    assert!(err.contains("unknown, revoked, or expired"), "got: {err}");
}

#[tokio::test]
async fn expired_ticket_refused() {
    let content = b"secret".to_vec();
    let fr = file_ref(&content, "s.bin");
    let nonce = Nonce::mint();
    let tickets = issued(nonce, REMOTE, Some(Utc::now() - ChronoDuration::hours(1)));
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path: write_temp(&content), file_ref: fr.clone() }, grant: Grant::Download };

    let err = run_refused(tickets, REMOTE, Some(offer), fr, nonce).await;
    assert!(err.contains("unknown, revoked, or expired"), "got: {err}");
}

/// `sem_auth_not_nonce_secrecy`: a valid, active nonce presented by a remote OTHER than the one
/// it was sealed to is refused — the nonce is an identifier, not a secret.
#[tokio::test]
async fn wrong_remote_refused() {
    let content = b"secret".to_vec();
    let fr = file_ref(&content, "s.bin");
    let nonce = Nonce::mint();
    let sealed_to = REMOTE;
    let stranger = [9u8; 32];
    let tickets = issued(nonce, sealed_to, None);
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path: write_temp(&content), file_ref: fr.clone() }, grant: Grant::Download };

    let err = run_refused(tickets, stranger, Some(offer), fr, nonce).await;
    assert!(err.contains("not sealed to your endpoint"), "got: {err}");
}

/// A `grant: sync` ticket is recognised and refused in Phase 1 (D18).
#[tokio::test]
async fn sync_grant_refused() {
    let content = b"secret".to_vec();
    let fr = file_ref(&content, "s.bin");
    let nonce = Nonce::mint();
    let tickets = issued(nonce, REMOTE, None);
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path: write_temp(&content), file_ref: fr.clone() }, grant: Grant::Sync };

    let err = run_refused(tickets, REMOTE, Some(offer), fr, nonce).await;
    assert!(err.contains("sync-grant tickets are not supported"), "got: {err}");
}

/// MR-14: a missing source fails honestly before any bytes stream (`sem_serve_verifies_source_present`).
#[tokio::test]
async fn missing_source_refused_before_streaming() {
    let fr = file_ref(b"whatever", "gone.bin");
    let nonce = Nonce::mint();
    let tickets = issued(nonce, REMOTE, None);
    let missing_path = tempfile::tempdir().unwrap().path().join("does-not-exist.bin");
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path: missing_path, file_ref: fr.clone() }, grant: Grant::Download };

    let err = run_refused(tickets, REMOTE, Some(offer), fr, nonce).await;
    assert!(err.contains("no longer present"), "got: {err}");
}

/// MR-14: a source whose size changed since issue fails honestly before any bytes stream.
#[tokio::test]
async fn changed_source_refused_before_streaming() {
    let original = b"original bytes here".to_vec();
    let fr = file_ref(&original, "c.bin");
    let nonce = Nonce::mint();
    let tickets = issued(nonce, REMOTE, None);
    let path = write_temp(b"a different, longer set of bytes now");
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path, file_ref: fr.clone() }, grant: Grant::Download };

    let err = run_refused(tickets, REMOTE, Some(offer), fr, nonce).await;
    assert!(err.contains("changed since the ticket was issued"), "got: {err}");
}

/// `offset > size` is a reasoned error, never a `u64` underflow (chorus H3).
#[tokio::test]
async fn offset_greater_than_size_refused() {
    let content = b"short".to_vec();
    let fr = file_ref(&content, "short.bin");
    let nonce = Nonce::mint();
    let tickets = issued(nonce, REMOTE, None);
    let offer = OfferRecord { nonce, payload: OfferPayload::File { path: write_temp(&content), file_ref: fr.clone() }, grant: Grant::Download };

    let (srv, cli) = tokio::io::duplex(64 * 1024);
    let (srv_r, srv_w) = tokio::io::split(srv);
    let (cli_r, cli_w) = tokio::io::split(cli);
    tokio::spawn(async move {
        let lookup = move |n: &Nonce| if n == &offer.nonce { Some(offer.clone()) } else { None };
        let _ = handle_request(srv_w, srv_r, REMOTE, &tickets, lookup, Utc::now()).await;
    });
    let dest = tempfile::tempdir().unwrap();
    let huge_offset = content.len() as u64 + 100;
    let err = pull_file(cli_w, cli_r, nonce, &fr, huge_offset, dest.path(), |_, _| {}).await.unwrap_err();
    match err {
        mascara_net::NetError::Refused(msg) => assert!(msg.contains("exceeds file size"), "got: {msg}"),
        other => panic!("expected a Refused error, got: {other}"),
    }
}

/// Oversize request frame refused BEFORE allocation (DESIGN §4: len cap 8 KiB).
#[tokio::test]
async fn oversize_request_frame_refused_before_allocation() {
    let tickets = IssuedTickets::default();
    let (srv, cli) = tokio::io::duplex(64 * 1024);
    let (srv_r, srv_w) = tokio::io::split(srv);
    let (mut cli_r, mut cli_w) = tokio::io::split(cli);
    tokio::spawn(async move {
        let _ = handle_request(srv_w, srv_r, REMOTE, &tickets, |_| None, Utc::now()).await;
    });

    // Declare a length far past the 8 KiB cap; never send the (huge) body — if the server
    // allocated before checking, this would attempt an 800 MiB allocation.
    cli_w.write_u32_le((mascara_net::listener::MAX_REQUEST_FRAME as u32) + 1).await.unwrap();
    cli_w.flush().await.unwrap();

    let status = cli_r.read_u8().await.unwrap();
    assert_eq!(status, 1);
    let elen = cli_r.read_u32_le().await.unwrap();
    let mut ebuf = vec![0u8; elen as usize];
    cli_r.read_exact(&mut ebuf).await.unwrap();
    let msg = String::from_utf8(ebuf).unwrap();
    assert!(msg.contains("too large"), "got: {msg}");
}

/// Malformed JSON in an otherwise well-framed request is a reasoned error, never a panic.
#[tokio::test]
async fn malformed_json_refused() {
    let tickets = IssuedTickets::default();
    let (srv, cli) = tokio::io::duplex(64 * 1024);
    let (srv_r, srv_w) = tokio::io::split(srv);
    let (mut cli_r, mut cli_w) = tokio::io::split(cli);
    tokio::spawn(async move {
        let _ = handle_request(srv_w, srv_r, REMOTE, &tickets, |_| None, Utc::now()).await;
    });

    let bad = b"{ not valid json";
    cli_w.write_u32_le(bad.len() as u32).await.unwrap();
    cli_w.write_all(bad).await.unwrap();
    cli_w.flush().await.unwrap();

    let status = cli_r.read_u8().await.unwrap();
    assert_eq!(status, 1);
    let elen = cli_r.read_u32_le().await.unwrap();
    let mut ebuf = vec![0u8; elen as usize];
    cli_r.read_exact(&mut ebuf).await.unwrap();
    let msg = String::from_utf8(ebuf).unwrap();
    assert!(msg.contains("malformed request"), "got: {msg}");
}

// --- Suite FOLDER / RESUME [M3] (TEST_PLAN.md §2) — listener + engine folder flow together ---

/// The three files every folder test serves (one in a subdir — the rel-path join must hold).
const FOLDER_FILES: &[(&str, &[u8])] = &[
    ("a.txt", b"alpha"),
    ("b.bin", b"bravo-bytes-bravo"),
    ("subs/en.srt", b"1\n00:00:01 --> 00:00:02\nmascara\n"),
];

/// Build a real on-disk folder + its encoded manifest + a folder `OfferRecord` whose
/// `manifest_path` holds the exact bytes `root_hash` commits to (the sender-side store).
fn folder_offer(nonce: Nonce) -> (OfferRecord, mascara_core::Manifest, mascara_core::FolderRef) {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let mut entries = Vec::new();
    for (rel, content) in FOLDER_FILES {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        entries.push(mascara_core::ManifestEntry {
            rel_path: (*rel).into(),
            size: content.len() as u64,
            sha256: Sha256::digest(content).into(),
            md5: [0u8; 16],
            mode: 0o644,
        });
    }
    let manifest = mascara_core::Manifest { v: mascara_core::MANIFEST_VERSION, entries };
    let bytes = mascara_core::encode_manifest(&manifest).unwrap();
    let root_hash: [u8; 32] = Sha256::digest(&bytes).into();
    let manifest_path = dir.path().join("stored-manifest.postcard");
    std::fs::write(&manifest_path, &bytes).unwrap();
    let folder_ref = mascara_core::FolderRef { name: "pack".into(), root_hash };
    let offer = OfferRecord {
        nonce,
        payload: OfferPayload::Folder {
            dir_path: dir.path().to_path_buf(),
            folder_ref: folder_ref.clone(),
            manifest_path,
        },
        grant: Grant::Download,
    };
    std::mem::forget(dir); // keep the tree alive for the test's duration
    (offer, manifest, folder_ref)
}

/// One duplex op against a freshly spawned `handle_request` server — the per-op stream shape
/// `dialer::pull_folder` produces over a real connection.
fn spawn_op(
    offer: OfferRecord,
) -> (impl tokio::io::AsyncWrite + Unpin, impl tokio::io::AsyncRead + Unpin) {
    let tickets = issued(offer.nonce, REMOTE, None);
    let (srv, cli) = tokio::io::duplex(256 * 1024);
    let (srv_r, srv_w) = tokio::io::split(srv);
    let (cli_r, cli_w) = tokio::io::split(cli);
    tokio::spawn(async move {
        let lookup = move |n: &Nonce| if n == &offer.nonce { Some(offer.clone()) } else { None };
        let _ = handle_request(srv_w, srv_r, REMOTE, &tickets, lookup, Utc::now()).await;
    });
    (cli_w, cli_r)
}

/// `sem_folderref_manifest_verified_before_use` + the folder happy path end-to-end: manifest op
/// (fully buffered, verified against `root_hash`, cached for resume) then per-entry file ops —
/// every file lands beneath the dest root, each hash-verified, subdirs included (D5).
#[tokio::test]
async fn folder_happy_path_manifest_then_entries() {
    let nonce = Nonce::mint();
    let (offer, _built, folder_ref) = folder_offer(nonce);
    let dest = tempfile::tempdir().unwrap();

    let (cli_w, cli_r) = spawn_op(offer.clone());
    let manifest =
        mascara_net::engine::fetch_manifest(cli_w, cli_r, nonce, &folder_ref, dest.path()).await.unwrap();
    assert_eq!(manifest.entries.len(), FOLDER_FILES.len());
    let cache = dest.path().join("manifests").join(format!("{}.postcard", nonce.to_hex()));
    assert!(cache.is_file(), "the verified manifest must be cached for resume (DESIGN §7)");

    let offer_for_ops = offer.clone();
    let open_stream = move |_e: &mascara_core::ManifestEntry| {
        let offer = offer_for_ops.clone();
        async move {
            let (w, r) = spawn_op(offer);
            Ok((
                Box::new(w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                Box::new(r) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
            ))
        }
    };
    let mut done_calls: Vec<String> = Vec::new();
    let pulled = mascara_net::engine::pull_folder(
        &manifest,
        nonce,
        dest.path(),
        open_stream,
        |_, _, _| {},
        |entry, _path| done_calls.push(entry.rel_path.clone()),
    )
    .await
    .unwrap();
    // codex #8: the per-entry completion callback fires once per landed entry, in order.
    assert_eq!(done_calls.len(), FOLDER_FILES.len(), "one done-callback per entry");
    assert_eq!(pulled.len(), FOLDER_FILES.len());
    for (rel, content) in FOLDER_FILES {
        let got = std::fs::read(dest.path().join(rel)).unwrap();
        assert_eq!(&got, content, "{rel} must land byte-identical beneath the dest root");
    }
}

/// A folder `file` op naming a path NOT in the committed manifest is refused — a folder ticket
/// serves only its manifest's entries (DESIGN §4), not just any file under the sender's dir.
#[tokio::test]
async fn folder_file_op_outside_manifest_refused() {
    let nonce = Nonce::mint();
    let (offer, _m, _fr) = folder_offer(nonce);
    let fr = file_ref(b"whatever", "not-in-manifest.bin");
    let err = run_refused(issued(nonce, REMOTE, None), REMOTE, Some(offer), fr, nonce).await;
    assert!(err.contains("not an entry in this folder's manifest"), "got: {err}");
}

/// A `manifest` op against a FILE ticket is refused with a reasoned error (recognise-and-refuse).
#[tokio::test]
async fn manifest_op_on_file_ticket_refused() {
    let content = b"just one file".to_vec();
    let fr = file_ref(&content, "one.bin");
    let nonce = Nonce::mint();
    let offer = OfferRecord {
        nonce,
        payload: OfferPayload::File { path: write_temp(&content), file_ref: fr },
        grant: Grant::Download,
    };
    let (cli_w, cli_r) = spawn_op(offer);
    let folder_ref = mascara_core::FolderRef { name: "x".into(), root_hash: [0u8; 32] };
    let dest = tempfile::tempdir().unwrap();
    let err = mascara_net::engine::fetch_manifest(cli_w, cli_r, nonce, &folder_ref, dest.path())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, mascara_net::NetError::Refused(msg) if msg.contains("applies only to folder tickets")),
        "got: {err}"
    );
}

/// `sem_folderref_manifest_verified_before_use`, server side: a sender-side manifest store whose
/// bytes drifted from the ticket's `root_hash` is refused at serve time — the listener never
/// streams a manifest that would not verify on the receiver (chorus H4, defense in depth).
#[tokio::test]
async fn tampered_manifest_store_refused_at_serve() {
    let nonce = Nonce::mint();
    let (offer, _m, folder_ref) = folder_offer(nonce);
    let OfferPayload::Folder { manifest_path, .. } = &offer.payload else { unreachable!() };
    // Tamper the sender-side store AFTER the offer committed to root_hash.
    std::fs::write(manifest_path, b"not the committed bytes").unwrap();

    let (cli_w, cli_r) = spawn_op(offer.clone());
    let dest = tempfile::tempdir().unwrap();
    let err = mascara_net::engine::fetch_manifest(cli_w, cli_r, nonce, &folder_ref, dest.path())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, mascara_net::NetError::Refused(msg) if msg.contains("no longer matches the ticket's root_hash")),
        "got: {err}"
    );
}

/// `sem_resume_offset_guarded` end-to-end through the REAL listener: round 1 (hand-rolled server)
/// truncates mid-file leaving a kept `.part`; round 2 runs `handle_request` for real — the client
/// auto-detects the partial, requests `offset = its length`, the listener seeks and streams the
/// tail, and the final hash covers the WHOLE file.
#[tokio::test]
async fn resume_through_listener_completes_partial() {
    let content: Vec<u8> = (0u32..25_000).flat_map(|i| i.to_le_bytes()).collect(); // 100 KB
    let fr = file_ref(&content, "resume.bin");
    let nonce = Nonce::mint();
    let dest = tempfile::tempdir().unwrap();

    // Round 1: promise the whole file, deliver a prefix, drop — the partial must survive.
    let cut = 30_000usize;
    let (srv, cli) = tokio::io::duplex(256 * 1024);
    let (srv_r, srv_w) = tokio::io::split(srv);
    let (cli_r, cli_w) = tokio::io::split(cli);
    let prefix = content[..cut].to_vec();
    let total = content.len() as u64;
    tokio::spawn(async move {
        let mut srv_r = srv_r;
        let mut srv_w = srv_w;
        let len = srv_r.read_u32_le().await.unwrap();
        let mut buf = vec![0u8; len as usize];
        srv_r.read_exact(&mut buf).await.unwrap();
        srv_w.write_u8(0).await.unwrap();
        srv_w.write_u64_le(total).await.unwrap();
        srv_w.write_all(&prefix).await.unwrap();
        // Drop both halves: the client sees a clean EOF short of `total` — a connection loss.
    });
    let err = pull_file(cli_w, cli_r, nonce, &fr, 0, dest.path(), |_, _| {}).await.unwrap_err();
    assert!(matches!(err, mascara_net::NetError::ConnectionLost(_)), "got: {err}");
    let part = dest.path().join("resume.bin.part");
    assert!(part.is_file(), "the partial must be KEPT on a connection loss (DESIGN §6.2)");
    assert_eq!(std::fs::metadata(&part).unwrap().len(), cut as u64);

    // Round 2: the real listener serves from the requested offset; the file completes and verifies.
    let offer = OfferRecord {
        nonce,
        payload: OfferPayload::File { path: write_temp(&content), file_ref: fr.clone() },
        grant: Grant::Download,
    };
    let (cli_w, cli_r) = spawn_op(offer);
    let final_path = pull_file(cli_w, cli_r, nonce, &fr, 0, dest.path(), |_, _| {}).await.unwrap();
    assert_eq!(std::fs::read(&final_path).unwrap(), content, "the resumed file must verify whole");
    assert!(!part.exists(), "the .part is consumed by the successful rename");
}

/// `sem_folder_paths_guarded`, client side: a manifest entry with a traversal rel-path is refused
/// BEFORE any stream is opened or any byte written — the open_stream callback must never fire.
#[tokio::test]
async fn folder_paths_guarded_before_any_stream() {
    let manifest = mascara_core::Manifest {
        v: mascara_core::MANIFEST_VERSION,
        entries: vec![mascara_core::ManifestEntry {
            rel_path: "../evil.bin".into(),
            size: 4,
            sha256: [0u8; 32],
            md5: [0u8; 16],
            mode: 0o644,
        }],
    };
    let dest = tempfile::tempdir().unwrap();
    let open_stream = |_e: &mascara_core::ManifestEntry| async move {
        panic!("no stream may be opened for a guarded rel-path");
        #[allow(unreachable_code)]
        Ok((
            Box::new(tokio::io::empty()) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
            Box::new(tokio::io::empty()) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        ))
    };
    let err = mascara_net::engine::pull_folder(
        &manifest,
        Nonce::mint(),
        dest.path(),
        open_stream,
        |_, _, _| {},
        |_, _| panic!("no entry may complete for a guarded rel-path"),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, mascara_net::NetError::Protocol(_)), "got: {err}");
    assert!(
        std::fs::read_dir(dest.path()).unwrap().next().is_none(),
        "nothing may be written for a guarded entry"
    );
}

/// `sem_folder_paths_guarded`, RECEIVER side, symlinked destination (codex #1, Unix): the lexical
/// guard cannot see that a directory already present in the destination is a symlink out of the
/// tree. `pull_folder` must resolve the created parent and refuse before opening any `.part` —
/// otherwise `<dest>/sub -> /outside` silently lands the download outside the chosen folder.
#[cfg(unix)]
#[tokio::test]
async fn folder_entry_through_symlinked_destination_dir_refused() {
    let outside = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    // A pre-existing symlink inside the destination pointing out of the tree.
    std::os::unix::fs::symlink(outside.path(), dest.path().join("sub")).unwrap();

    let manifest = mascara_core::Manifest {
        v: mascara_core::MANIFEST_VERSION,
        entries: vec![mascara_core::ManifestEntry {
            // Lexically impeccable: no `..`, no absolute, no reserved name.
            rel_path: "sub/loot.bin".into(),
            size: 4,
            sha256: [0u8; 32],
            md5: [0u8; 16],
            mode: 0o644,
        }],
    };
    let open_stream = |_e: &mascara_core::ManifestEntry| async move {
        panic!("no stream may be opened once the destination resolves outside the root");
        #[allow(unreachable_code)]
        Ok((
            Box::new(tokio::io::empty()) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
            Box::new(tokio::io::empty()) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        ))
    };
    let err = mascara_net::engine::pull_folder(
        &manifest,
        Nonce::mint(),
        dest.path(),
        open_stream,
        |_, _, _| {},
        |_, _| panic!("nothing may complete"),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, mascara_net::NetError::Protocol(msg) if msg.contains("resolves outside")),
        "got: {err}"
    );
    assert!(
        std::fs::read_dir(outside.path()).unwrap().next().is_none(),
        "nothing may be written outside the chosen destination"
    );
}

/// `sem_folder_paths_guarded`, server side (Unix): a manifest entry whose on-disk name is a
/// symlink pointing outside the shared folder is refused by the listener's canonicalize guard
/// (M8 mining) — committed hash or not, the bytes never leave the root.
#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_refused_at_serve() {
    use sha2::{Digest, Sha256};
    // An out-of-root secret the symlink points at.
    let outside = tempfile::tempdir().unwrap();
    let secret_path = outside.path().join("secret.bin");
    let secret = b"outside the shared root";
    std::fs::write(&secret_path, secret).unwrap();

    // A folder whose manifest legitimately lists "esc.bin" (size/hash match the target, so only
    // the path guard can refuse), but whose on-disk "esc.bin" is a symlink escaping the root.
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(&secret_path, dir.path().join("esc.bin")).unwrap();
    let entries = vec![mascara_core::ManifestEntry {
        rel_path: "esc.bin".into(),
        size: secret.len() as u64,
        sha256: Sha256::digest(secret).into(),
        md5: [0u8; 16],
        mode: 0o644,
    }];
    let manifest = mascara_core::Manifest { v: mascara_core::MANIFEST_VERSION, entries };
    let bytes = mascara_core::encode_manifest(&manifest).unwrap();
    let root_hash: [u8; 32] = Sha256::digest(&bytes).into();
    let manifest_path = dir.path().join("stored.postcard");
    std::fs::write(&manifest_path, &bytes).unwrap();

    let nonce = Nonce::mint();
    let offer = OfferRecord {
        nonce,
        payload: OfferPayload::Folder {
            dir_path: dir.path().to_path_buf(),
            folder_ref: mascara_core::FolderRef { name: "esc".into(), root_hash },
            manifest_path,
        },
        grant: Grant::Download,
    };
    let fr = FileRef { name: "esc.bin".into(), size: secret.len() as u64, sha256: Sha256::digest(secret).into(), md5: [0u8; 16], mime: None };
    let err = run_refused(issued(nonce, REMOTE, None), REMOTE, Some(offer), fr, nonce).await;
    assert!(err.contains("symlink escape refused"), "got: {err}");
}

// --- test helpers ---

fn write_temp(content: &[u8]) -> std::path::PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.bin");
    std::fs::write(&path, content).unwrap();
    // Leak the tempdir so the file survives for the duration of the test (dropped at process exit).
    std::mem::forget(dir);
    path
}

/// Run one request expected to be refused, returning the error message text.
async fn run_refused(
    tickets: IssuedTickets,
    remote_id: [u8; 32],
    offer: Option<OfferRecord>,
    file_ref: FileRef,
    nonce: Nonce,
) -> String {
    let (srv, cli) = tokio::io::duplex(64 * 1024);
    let (srv_r, srv_w) = tokio::io::split(srv);
    let (cli_r, cli_w) = tokio::io::split(cli);
    tokio::spawn(async move {
        let lookup = move |n: &Nonce| offer.clone().filter(|o| &o.nonce == n);
        let _ = handle_request(srv_w, srv_r, remote_id, &tickets, lookup, Utc::now()).await;
    });
    let dest = tempfile::tempdir().unwrap();
    match pull_file(cli_w, cli_r, nonce, &file_ref, 0, dest.path(), |_, _| {}).await {
        Err(mascara_net::NetError::Refused(msg)) => msg,
        other => panic!("expected a Refused error, got: {other:?}"),
    }
}
