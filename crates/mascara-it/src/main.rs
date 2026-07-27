//! mascara-it — L2 loopback integration harness (TEST_PLAN.md §1: "two real iroh endpoints, one
//! process/localhost"). Mining map: the quarry's `p2p_it.rs` harness pattern (plain sequential
//! checks, exit nonzero on any failure) — here scoped to the M2 brief's checks:
//!
//! 1. the full ticket lifecycle: issue → seal → open → consent → dial → transfer of a real temp
//!    file, SHA-256 verified end to end.
//! 2. revocation-live: revoke the nonce, dial again → refused with the reasoned error.
//! 3. `sem_auth_not_nonce_secrecy`: a THIRD identity (not the sealed-to recipient) presents the
//!    valid, cleartext nonce over its own connection → refused (identity, not nonce secrecy, is
//!    what authorizes).
//! 4. cancel mid-transfer (DESIGN §4, TEST_PLAN §2 Suite XFER): the serving side closes the QUIC
//!    connection with application error code 1 + reason `"cancelled"` while a large pull is still
//!    in flight → the receiver surfaces `NetError::Cancelled` ("cancelled by peer"), not the
//!    generic connection-lost class, and no final (non-`.part`) file is produced.
//! 5. the other side of that distinction: an abrupt close with a *different* application error
//!    code → the receiver surfaces the generic connection-lost class, never `Cancelled`.
//!
//! Every check prints its own line; the process exits nonzero if any check fails.

use std::path::PathBuf;

use chrono::Utc;
use mascara_core::{FileDescriptor, FileStore, Identity, IssuedRecord, Nonce, Registry, ShareDescriptor, Ticket};
use mascara_net::listener::{run as run_listener, OfferStore};
use mascara_net::{consent, dialer, endpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let results = [
        ("full transfer (issue -> seal -> open -> consent -> dial -> verify)", check_full_transfer().await),
        ("revocation-live (revoke -> refused)", check_revocation_live().await),
        ("wrong remote_id (nonce is not a secret)", check_wrong_remote_refused().await),
        ("cancel mid-transfer (app close code 1 -> cancelled by peer)", check_cancel_mid_transfer().await),
        ("abrupt close, non-1 code (-> connection lost, not cancelled)", check_abrupt_close_is_connection_lost().await),
        ("folder transfer (manifest verify -> per-entry pull -> subdirs land)", check_folder_transfer().await),
        ("folder resume (interrupt mid-file -> partial kept -> resumed whole)", check_folder_resume().await),
    ];

    let mut failed = false;
    for (name, result) in results {
        match result {
            Ok(()) => println!("[mascara-it] ok   - {name}"),
            Err(e) => {
                println!("[mascara-it] FAIL - {name}");
                eprintln!("  detail: {e:#}");
                failed = true;
            }
        }
    }

    if failed {
        eprintln!("[mascara-it] one or more checks failed");
        std::process::ExitCode::FAILURE
    } else {
        println!("[mascara-it] all checks passed");
        std::process::ExitCode::SUCCESS
    }
}

/// Shared fixture: a sender with a real file + a running listener, and the receiver's already-
/// opened ticket for it. Each check tears this down itself (endpoints closed, listener aborted).
struct Setup {
    _sender_home: tempfile::TempDir,
    _src_dir: tempfile::TempDir,
    sender_home_path: PathBuf,
    sender_ep: iroh::Endpoint,
    receiver_id: Identity,
    opened: Ticket,
    content: Vec<u8>,
    listener_task: tokio::task::JoinHandle<()>,
}

async fn setup() -> anyhow::Result<Setup> {
    let sender_home_dir = tempfile::tempdir()?;
    let sender_home_path = sender_home_dir.path().to_path_buf();
    let src_dir = tempfile::tempdir()?;

    let sender_id = Identity::mint();
    let receiver_id = Identity::mint();

    let content = b"mascara-it integration payload\n".repeat(500);
    let src_path = src_dir.path().join("payload.bin");
    std::fs::write(&src_path, &content)?;

    let descriptor = ShareDescriptor::File(FileDescriptor {
        name: "payload.bin".into(),
        size: content.len() as u64,
        sha256: sha256_of(&content),
        md5: [0u8; 16],
        mime: None,
        link_assertion: None,
    });

    // Two real iroh endpoints, one process, loopback (discovery off by construction, relay
    // disabled — see mascara_net::endpoint's module docs).
    let sender_ep = endpoint::build_loopback_endpoint(&sender_id).await?;
    let sender_addrs = endpoint::local_endpoint_addrs(&sender_ep).await;

    let nonce = Nonce::mint();
    let file_descriptor = match descriptor {
        ShareDescriptor::File(f) => f,
        ShareDescriptor::Folder(_) => unreachable!("setup() uses a File descriptor"),
    };
    let ticket = file_descriptor.into_file_ticket(
        sender_addrs,
        sender_id.card().payload_bytes(),
        None,
        nonce,
    );
    let sealed = ticket.seal(&receiver_id.card())?;

    let registry = Registry::new(FileStore::at(&sender_home_path));
    registry.issue(IssuedRecord::new(
        nonce,
        Some("payload.bin".into()),
        Utc::now(),
        None,
        receiver_id.card().transport_pk,
    ))?;
    let offers = OfferStore::at(&sender_home_path);
    offers.record_file(
        nonce,
        src_path,
        ticket.file_ref().expect("a File ticket carries a file_ref").clone(),
        ticket.grant,
    )?;

    let listener_ep = sender_ep.clone();
    let listener_home = sender_home_path.clone();
    let listener_task = tokio::spawn(async move {
        let _ = run_listener(listener_ep, listener_home).await;
    });

    let opened = Ticket::open(&sealed, &receiver_id)?;

    Ok(Setup {
        _sender_home: sender_home_dir,
        _src_dir: src_dir,
        sender_home_path,
        sender_ep,
        receiver_id,
        opened,
        content,
        listener_task,
    })
}

impl Setup {
    async fn teardown(self) {
        self.sender_ep.close().await;
        self.listener_task.abort();
    }
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

async fn check_full_transfer() -> anyhow::Result<()> {
    let s = setup().await?;
    let ack = consent::acknowledge_ip_exposure();
    let receiver_ep = endpoint::build_loopback_endpoint(&s.receiver_id).await?;
    let dest = tempfile::tempdir()?;

    let downloaded = dialer::pull(&receiver_ep, &s.opened, ack, dest.path(), |_, _| {}).await?;
    let got = std::fs::read(&downloaded)?;
    anyhow::ensure!(got == s.content, "downloaded content did not match the source file");
    anyhow::ensure!(
        sha256_of(&got) == s.opened.file_ref().expect("file ticket").sha256,
        "sha256 did not verify"
    );

    receiver_ep.close().await;
    s.teardown().await;
    Ok(())
}

async fn check_revocation_live() -> anyhow::Result<()> {
    let s = setup().await?;
    let registry = Registry::new(FileStore::at(&s.sender_home_path));
    registry.revoke(&s.opened.nonce)?;

    let ack = consent::acknowledge_ip_exposure();
    let receiver_ep = endpoint::build_loopback_endpoint(&s.receiver_id).await?;
    let dest = tempfile::tempdir()?;
    let result = dialer::pull(&receiver_ep, &s.opened, ack, dest.path(), |_, _| {}).await;

    receiver_ep.close().await;
    match result {
        Err(mascara_net::NetError::Refused(msg)) if msg.contains("unknown, revoked, or expired") => {
            s.teardown().await;
            Ok(())
        }
        Err(other) => {
            s.teardown().await;
            anyhow::bail!("expected a revoked-ticket refusal, got a different error: {other}")
        }
        Ok(_) => {
            s.teardown().await;
            anyhow::bail!("a revoked ticket must never succeed, but the transfer completed")
        }
    }
}

async fn check_wrong_remote_refused() -> anyhow::Result<()> {
    let s = setup().await?;

    // A third identity, NOT the recipient this ticket was sealed to. It cannot open the sealed
    // ticket string (crypto_box seals to the real recipient's key) — but the nonce rides in
    // clear on the wire (DESIGN §4: an identifier, not a secret), so it presents the SAME nonce
    // straight over its own connection to prove the sender authorizes by identity, not by nonce
    // secrecy (`sem_auth_not_nonce_secrecy`).
    let stranger_id = Identity::mint();
    let stranger_ep = endpoint::build_loopback_endpoint(&stranger_id).await?;
    let addr = endpoint::endpoint_addr_from_ticket(&s.opened)?;
    let conn = stranger_ep.connect(addr, endpoint::XFER_ALPN).await?;
    let (send, recv) = conn.open_bi().await?;
    let dest = tempfile::tempdir()?;

    let result =
        mascara_net::engine::pull_file(send, recv, s.opened.nonce, s.opened.file_ref().expect("file ticket"), 0, dest.path(), |_, _| {})
            .await;
    conn.close(0u32.into(), b"");
    stranger_ep.close().await;

    match result {
        Err(mascara_net::NetError::Refused(msg)) if msg.contains("not sealed to your endpoint") => {
            s.teardown().await;
            Ok(())
        }
        Err(other) => {
            s.teardown().await;
            anyhow::bail!("expected a wrong-remote refusal, got a different error: {other}")
        }
        Ok(_) => {
            s.teardown().await;
            anyhow::bail!("a stranger presenting someone else's nonce must never succeed")
        }
    }
}

// ------------------------------------------------------------------------------------------
// Checks 4/5: the DESIGN §4 cancel/close-code distinction. These don't go through
// `run_listener`/`handle_request` — that server loop has no hook to force-close a connection
// mid-copy, and adding one would be more than this gap needs. Instead the SERVING side here is a
// minimal hand-rolled `/mascara/xfer/1` responder (same wire shape as `listener::handle_request`,
// same technique as that module's own `error_response_survives_connection_close` test), so the
// harness itself controls exactly when and with what code the connection closes. The RECEIVING
// side is the real, unmodified `dialer::pull` — the one piece of production code this is actually
// testing.
// ------------------------------------------------------------------------------------------

/// Run one real two-endpoint pull of a large, patterned file where the serving side force-closes
/// the connection — with `(close_code, close_reason)` — as soon as it has observed the receiver
/// make progress (never a bare sleep: `on_progress`'s first `done > 0` call is what unblocks the
/// close, so the close is provably concurrent with real bytes in flight, however fast or slow the
/// loopback link runs). Returns `dialer::pull`'s result plus the destination dir for the caller's
/// file-system assertions.
async fn run_cancellable_transfer(
    close_code: u32,
    close_reason: &'static [u8],
) -> anyhow::Result<(Result<PathBuf, mascara_net::NetError>, tempfile::TempDir)> {
    let sender_id = Identity::mint();
    let receiver_id = Identity::mint();
    let sender_ep = endpoint::build_loopback_endpoint(&sender_id).await?;
    let receiver_ep = endpoint::build_loopback_endpoint(&receiver_id).await?;
    let sender_addrs = endpoint::local_endpoint_addrs(&sender_ep).await;

    // Tens of MiB of patterned bytes (same repeated-string technique as `setup()`, just bigger) —
    // large enough that the serve loop is still mid-stream when the close lands.
    let content = b"mascara-it cancel-mid-transfer payload\n".repeat(900_000); // ~34 MiB
    let sha256 = sha256_of(&content);

    let descriptor = ShareDescriptor::File(FileDescriptor {
        name: "big.bin".into(),
        size: content.len() as u64,
        sha256,
        md5: [0u8; 16],
        mime: None,
        link_assertion: None,
    });
    let nonce = Nonce::mint();
    let file_descriptor = match descriptor {
        ShareDescriptor::File(f) => f,
        ShareDescriptor::Folder(_) => unreachable!("run_cancellable_transfer uses a File descriptor"),
    };
    let ticket = file_descriptor.into_file_ticket(
        sender_addrs,
        sender_id.card().payload_bytes(),
        None,
        nonce,
    );
    let sealed = ticket.seal(&receiver_id.card())?;
    let opened = Ticket::open(&sealed, &receiver_id)?;

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<()>(1);

    let server_content = content.clone();
    let server_task = tokio::spawn(async move {
        let Some(incoming) = sender_ep.accept().await else { return };
        let Ok(conn) = incoming.await else { return };
        let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };

        // Drain the request frame (u32-LE len + JSON, DESIGN §4) so the client's write completes.
        // Its contents don't matter here — auth/routing are already covered by the other checks.
        let Ok(len) = recv.read_u32_le().await else { return };
        let mut req_buf = vec![0u8; len as usize];
        if recv.read_exact(&mut req_buf).await.is_err() {
            return;
        }

        let _ = send.write_u8(0).await;
        let _ = send.write_u64_le(server_content.len() as u64).await;

        const CHUNK: usize = 256 * 1024; // matches engine::pull_file's read chunk size
        for chunk in server_content.chunks(CHUNK) {
            if send.write_all(chunk).await.is_err() {
                break;
            }
            if progress_rx.try_recv().is_ok() {
                conn.close(close_code.into(), close_reason);
                sender_ep.close().await;
                return;
            }
        }
        // The whole file streamed before progress was observed — should not happen at this size
        // over loopback, but fail loudly rather than silently pass a check that never exercised
        // the close path it claims to.
        conn.close(0u32.into(), b"");
        sender_ep.close().await;
    });

    let ack = consent::acknowledge_ip_exposure();
    let dest = tempfile::tempdir()?;
    let result = dialer::pull(&receiver_ep, &opened, ack, dest.path(), move |done, _total| {
        if done > 0 {
            let _ = progress_tx.try_send(());
        }
    })
    .await;

    receiver_ep.close().await;
    let _ = server_task.await;
    Ok((result, dest))
}

async fn check_cancel_mid_transfer() -> anyhow::Result<()> {
    let (result, dest) = run_cancellable_transfer(1, b"cancelled").await?;

    match result {
        Err(mascara_net::NetError::Cancelled) => {}
        Err(other) => anyhow::bail!("expected the peer-cancel error, got a different one: {other}"),
        Ok(_) => anyhow::bail!("a mid-transfer cancel must never complete the download"),
    }

    // Delete-on-cancel (DESIGN §4): a cancelled transfer leaves NOTHING behind — neither a final
    // file nor a `.part` remnant (the engine removes the partial on every error exit).
    let leftover = std::fs::read_dir(dest.path())?.filter_map(|e| e.ok()).count();
    anyhow::ensure!(leftover == 0, "a mid-transfer cancel must leave the destination empty (no final file, no .part)");
    Ok(())
}

async fn check_abrupt_close_is_connection_lost() -> anyhow::Result<()> {
    let (result, dest) = run_cancellable_transfer(2, b"boom").await?;

    match result {
        Err(mascara_net::NetError::ConnectionLost(_)) => {
            // M3 (DESIGN §6.2): a connection loss KEEPS the partial — that is the resumable state.
            // Only a peer cancel (code 1) discards it (`sem_partials_deleted_on_cancel`).
            anyhow::ensure!(
                dest.path().join("big.bin.part").is_file(),
                "a connection loss must keep the .part for resume (M3 D-resume)"
            );
            Ok(())
        }
        Err(mascara_net::NetError::Cancelled) => {
            anyhow::bail!("an abrupt close with a non-1 code must not be classified as a peer cancel")
        }
        Err(other) => anyhow::bail!("expected the connection-lost class, got a different error: {other}"),
        Ok(_) => anyhow::bail!("an abrupt server close must never complete the download"),
    }
}

// --- M3 folder checks (Suite FOLDER/RESUME, TEST_PLAN §2) --------------------------------------

/// The folder fixture's entries: a small first file, a LARGE middle file (the resume check
/// interrupts inside it), and a small subdir entry (the rel-path join must hold over real iroh).
fn folder_fixture_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("a.txt", b"first, small".to_vec()),
        ("big.bin", b"mascara-it folder resume payload\n".repeat(250_000)), // ~8 MiB
        ("subs/z.srt", b"1\n00:00:01 --> 00:00:02\nlast, in a subdir\n".to_vec()),
    ]
}

/// Folder analog of [`setup`]: a real on-disk folder + folder descriptor -> v2 folder ticket,
/// registry + folder offer recorded (manifest bytes stored + verified), real listener running,
/// receiver's ticket opened.
struct FolderSetup {
    _sender_home: tempfile::TempDir,
    _src_dir: tempfile::TempDir,
    sender_ep: iroh::Endpoint,
    receiver_id: Identity,
    opened: Ticket,
    files: Vec<(&'static str, Vec<u8>)>,
    listener_task: tokio::task::JoinHandle<()>,
}

async fn folder_setup() -> anyhow::Result<FolderSetup> {
    let sender_home_dir = tempfile::tempdir()?;
    let sender_home_path = sender_home_dir.path().to_path_buf();
    let src_dir = tempfile::tempdir()?;

    let sender_id = Identity::mint();
    let receiver_id = Identity::mint();

    let files = folder_fixture_files();
    let mut entries = Vec::new();
    for (rel, content) in &files {
        let path = src_dir.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("fixture rel-paths have parents"))?;
        std::fs::write(&path, content)?;
        entries.push(mascara_core::FolderEntry {
            rel_path: (*rel).into(),
            size: content.len() as u64,
            sha256: sha256_of(content),
            md5: [0u8; 16],
            mode: 0o644,
        });
    }
    // The descriptor's claimed root_hash must match its own entries (Hoardbook's two claims are
    // consistency-checked at mint) — compute it the way Hoardbook would: over the postcard bytes.
    let manifest = mascara_core::Manifest { v: mascara_core::MANIFEST_VERSION, entries: entries.iter().map(|e| mascara_core::ManifestEntry {
        rel_path: e.rel_path.clone(), size: e.size, sha256: e.sha256, md5: e.md5, mode: e.mode,
    }).collect() };
    let root_hash = sha256_of(&mascara_core::encode_manifest(&manifest)?);
    let descriptor = mascara_core::FolderDescriptor {
        name: "fixture-pack".into(),
        root_hash,
        entries,
        link_assertion: None,
    };

    let sender_ep = endpoint::build_loopback_endpoint(&sender_id).await?;
    let sender_addrs = endpoint::local_endpoint_addrs(&sender_ep).await;

    let nonce = Nonce::mint();
    let (ticket, manifest_bytes) =
        descriptor.into_folder_ticket(sender_addrs, sender_id.card().payload_bytes(), None, nonce)?;
    let sealed = ticket.seal(&receiver_id.card())?;

    let registry = Registry::new(FileStore::at(&sender_home_path));
    registry.issue(IssuedRecord::new(
        nonce,
        Some("fixture-pack".into()),
        Utc::now(),
        None,
        receiver_id.card().transport_pk,
    ))?;
    let offers = OfferStore::at(&sender_home_path);
    offers.record_folder(
        nonce,
        src_dir.path().to_path_buf(),
        ticket.folder_ref().expect("a Folder ticket carries a folder_ref").clone(),
        manifest_bytes,
        ticket.grant,
    )?;

    let listener_ep = sender_ep.clone();
    let listener_task = tokio::spawn(async move {
        let _ = run_listener(listener_ep, sender_home_path).await;
    });

    let opened = Ticket::open(&sealed, &receiver_id)?;

    Ok(FolderSetup {
        _sender_home: sender_home_dir,
        _src_dir: src_dir,
        sender_ep,
        receiver_id,
        opened,
        files,
        listener_task,
    })
}

impl FolderSetup {
    async fn teardown(self) {
        self.sender_ep.close().await;
        self.listener_task.abort();
    }
}

/// Full folder lifecycle over real iroh: stage-1 consent -> `fetch_manifest` (verified + cached)
/// -> stage-2 -> `pull_folder` -> every entry lands beneath the dest root (subdir included),
/// hash-verified, through the REAL `listener::run` accept loop (one connection, N bi-streams).
async fn check_folder_transfer() -> anyhow::Result<()> {
    let s = folder_setup().await?;
    let receiver_ep = endpoint::build_loopback_endpoint(&s.receiver_id).await?;
    let dest = tempfile::tempdir()?;

    let ack = consent::acknowledge_ip_exposure();
    let manifest = dialer::fetch_manifest(&receiver_ep, &s.opened, ack, dest.path()).await?;
    anyhow::ensure!(manifest.entries.len() == s.files.len(), "manifest must list every fixture entry");
    let cache = dest.path().join("manifests").join(format!("{}.postcard", s.opened.nonce.to_hex()));
    anyhow::ensure!(cache.is_file(), "the verified manifest must be cached beside the destination");

    let ack2 = consent::acknowledge_ip_exposure();
    let mut done_order: Vec<String> = Vec::new();
    let pulled = dialer::pull_folder(
        &receiver_ep,
        &s.opened,
        ack2,
        &manifest,
        dest.path(),
        |_, _, _| {},
        |entry, _path| done_order.push(entry.rel_path.clone()),
    )
    .await?;
    anyhow::ensure!(pulled.len() == s.files.len(), "every entry must be pulled");
    // codex #8: the per-entry completion callback fires for each landed entry.
    anyhow::ensure!(
        done_order.len() == s.files.len(),
        "expected one completion callback per entry, got {}",
        done_order.len()
    );
    for (rel, content) in &s.files {
        let got = std::fs::read(dest.path().join(rel))
            .map_err(|e| anyhow::anyhow!("{rel} missing after the pull: {e}"))?;
        anyhow::ensure!(&got == content, "{rel} must land byte-identical (folder hash gate)");
    }

    receiver_ep.close().await;
    s.teardown().await;
    Ok(())
}

/// Interrupt a folder pull mid-way through the LARGE middle entry (receiver-side task abort — the
/// engine's `.part` stays on disk exactly as a crash/drop would leave it), then re-dial and pull
/// again: completed entries stay, the partial resumes at its offset, and the whole folder
/// verifies (`sem_resume_offset_guarded` / FQ3 over real iroh).
async fn check_folder_resume() -> anyhow::Result<()> {
    let s = folder_setup().await?;
    let receiver_ep = endpoint::build_loopback_endpoint(&s.receiver_id).await?;
    let dest = tempfile::tempdir()?;

    let ack = consent::acknowledge_ip_exposure();
    let manifest = dialer::fetch_manifest(&receiver_ep, &s.opened, ack, dest.path()).await?;

    // Pull in a spawned task; the progress callback trips once past 1 MiB into big.bin, then
    // sleeps long enough for the abort below to land at the task's next await point.
    let (tripped_tx, tripped_rx) = std::sync::mpsc::channel::<()>();
    let ep2 = receiver_ep.clone();
    let opened2 = s.opened.clone();
    let manifest2 = manifest.clone();
    let dest_path = dest.path().to_path_buf();
    let pull_task = tokio::spawn(async move {
        let ack = consent::acknowledge_ip_exposure();
        let mut already_tripped = false;
        dialer::pull_folder(
            &ep2,
            &opened2,
            ack,
            &manifest2,
            &dest_path,
            move |rel, done, _total| {
                if rel == "big.bin" && done > 1024 * 1024 && !already_tripped {
                    already_tripped = true;
                    let _ = tripped_tx.send(());
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            },
            |_, _| {},
        )
        .await
    });
    tripped_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| anyhow::anyhow!("the pull never reached 1 MiB into big.bin"))?;
    pull_task.abort();
    let _ = pull_task.await; // JoinError(cancelled) expected

    let part = dest.path().join("big.bin.part");
    anyhow::ensure!(part.is_file(), "the interrupted middle entry must leave a resumable .part");
    let part_len = std::fs::metadata(&part)?.len();
    let big_len = s.files[1].1.len() as u64;
    anyhow::ensure!(part_len > 0 && part_len < big_len, "the partial must be a strict prefix (got {part_len} of {big_len})");
    anyhow::ensure!(
        dest.path().join("a.txt").is_file(),
        "the entry completed before the interrupt must remain"
    );

    // Second attempt: fresh manifest fetch (cache must agree — FQ3) + pull resumes the partial.
    let ack = consent::acknowledge_ip_exposure();
    let manifest = dialer::fetch_manifest(&receiver_ep, &s.opened, ack, dest.path()).await?;
    let ack2 = consent::acknowledge_ip_exposure();
    dialer::pull_folder(&receiver_ep, &s.opened, ack2, &manifest, dest.path(), |_, _, _| {}, |_, _| {})
        .await?;

    for (rel, content) in &s.files {
        let got = std::fs::read(dest.path().join(rel))
            .map_err(|e| anyhow::anyhow!("{rel} missing after the resume: {e}"))?;
        anyhow::ensure!(&got == content, "{rel} must verify whole after the resume");
    }
    anyhow::ensure!(!part.exists(), "the resumed partial is consumed by the final rename");

    receiver_ep.close().await;
    s.teardown().await;
    Ok(())
}
