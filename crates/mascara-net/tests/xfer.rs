//! Suite XFER [M2] (TEST_PLAN.md §2) — the full request/response round trip over
//! `tokio::io::duplex` (L1, no QUIC — the quarry's proven technique), wiring
//! `mascara_net::listener::handle_request` (server) against `mascara_net::engine::pull_file`
//! (client) together. Real-iroh scenarios (the drain race, cancel close-code distinction) live
//! in `mascara-net`'s own `#[cfg(test)]` modules / `mascara-it` — see those for why.

use chrono::{Duration as ChronoDuration, Utc};
use mascara_core::{FileRef, Grant, IssuedRecord, IssuedTickets, Nonce};
use mascara_net::engine::pull_file;
use mascara_net::listener::{handle_request, OfferRecord};
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
    let offer = OfferRecord { nonce, path: write_temp(&content), file_ref: fr.clone(), grant: Grant::Download };

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
    let offer = OfferRecord { nonce, path: write_temp(&content), file_ref: fr.clone(), grant: Grant::Download };

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
    let offer = OfferRecord { nonce, path: write_temp(&content), file_ref: fr.clone(), grant: Grant::Download };

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
    let offer = OfferRecord { nonce, path: write_temp(&content), file_ref: fr.clone(), grant: Grant::Download };

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
    let offer = OfferRecord { nonce, path: write_temp(&content), file_ref: fr.clone(), grant: Grant::Sync };

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
    let offer = OfferRecord { nonce, path: missing_path, file_ref: fr.clone(), grant: Grant::Download };

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
    let offer = OfferRecord { nonce, path, file_ref: fr.clone(), grant: Grant::Download };

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
    let offer = OfferRecord { nonce, path: write_temp(&content), file_ref: fr.clone(), grant: Grant::Download };

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
