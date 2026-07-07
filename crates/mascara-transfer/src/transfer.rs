//! iroh-based P2P file transfer with the v0.9 binding gate (H2/H17).
//!
//! Protocol (`/hoardbook/xfer/1`):
//!   Client → Server  [u32-LE token-len] [binding-token JSON]      ← H17, the FIRST frame
//!                     [u32-LE request-len] [JSON XferRequest]
//!   Server → Client  [u8 status: 0=ok 1=error]
//!     ok    → [u64-LE file-size] [file bytes]
//!     error → [u32-LE msg-len]  [UTF-8 error message]
//!
//! **H17 (server):** the requester presents an `npub`-signed binding token as the first
//! length-prefixed frame. The server caps the declared length *before* allocating
//! (`check_token_frame_len`), verifies the token (`verify_binding_token` → the requester's npub),
//! matches the token's bound node key to `conn.remote_id()` (the QUIC-authenticated remote), then
//! gates `require_follow` on the **npub** (`follower_gate`) — never a retired per-node id. The pure
//! trust logic lives in `hb-core::gate`; this file is the I/O caller.
//!
//! **H2 (client):** the downloader resolves the peer's node key from their *verified presence
//! binding* (`hb-core::resolve_node_key`) before any QUIC — see `commands::sharing` — so a lying
//! relay can't redirect a download to an impostor.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicU32, AtomicU64, Ordering}};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use globset::{Glob, GlobSetBuilder};
use iroh::{Endpoint, EndpointAddr};
use nostr::prelude::ToBech32;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, oneshot};

use crate::store::DataStore;

/// Freshness window a presented binding token must fall within (matches the gate's skew window).
pub const TOKEN_MAX_AGE: Duration = Duration::from_secs(300);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Download registry — tracks in-flight downloads and their cancel tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct DownloadProgressEvent {
    pub id: u64,
    pub filename: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bytes_per_sec: u64,
    pub status: DownloadStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadStatus {
    Active,
    Done,
    Cancelled,
    Error,
}

pub struct DownloadRegistry {
    next_id: AtomicU64,
    cancels: Mutex<HashMap<u64, oneshot::Sender<()>>>,
    /// Counts concurrent active server-side downloads for enforcing download_limit.
    active_downloads: AtomicU32,
}

impl DownloadRegistry {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            cancels: Mutex::new(HashMap::new()),
            active_downloads: AtomicU32::new(0),
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Increment the active-download counter and return the new count.
    pub fn acquire_slot(&self) -> u32 {
        self.active_downloads.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Decrement the active-download counter.
    pub fn release_slot(&self) {
        self.active_downloads.fetch_sub(1, Ordering::Relaxed);
    }

    pub async fn register(&self, id: u64) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.cancels.lock().await.insert(id, tx);
        rx
    }

    pub async fn cancel(&self, id: u64) -> bool {
        if let Some(tx) = self.cancels.lock().await.remove(&id) {
            tx.send(()).is_ok()
        } else {
            false
        }
    }

    pub async fn remove(&self, id: u64) {
        self.cancels.lock().await.remove(&id);
    }
}

pub type SharedDownloadRegistry = Arc<DownloadRegistry>;

pub const XFER_ALPN: &[u8] = b"/hoardbook/xfer/1";

#[derive(Serialize, Deserialize)]
struct XferRequest {
    slug: String,
    path: String,
    // The requester identity is NOT a self-claimed JSON field — it is the npub authenticated by
    // the binding token in the preceding frame, matched to conn.remote_id(). See handle_xfer_stream.
}

// ---------------------------------------------------------------------------
// Server — runs as a background task on the local iroh endpoint
// ---------------------------------------------------------------------------

/// The npubs of every saved contact — the H17 follower allow-list.
fn follower_npubs(store: &DataStore) -> Vec<nostr::PublicKey> {
    store
        .list_contacts()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| hb_core::identity::parse_npub(&c.npub).ok())
        .collect()
}

/// Inner handler for a single xfer request/response. Extracted with generic stream bounds so it
/// can be tested without real QUIC networking. `remote_node_key` is the QUIC-authenticated remote
/// endpoint id (`conn.remote_id()`), the only trustworthy node identity.
pub(crate) async fn handle_xfer_stream(
    mut send: impl tokio::io::AsyncWrite + Unpin,
    mut recv: impl tokio::io::AsyncRead + Unpin,
    remote_node_key: &[u8; 32],
    store: &DataStore,
    registry: &SharedDownloadRegistry,
) -> Result<()> {
    // ── H17 frame 1: the binding token (verified before any file request is parsed) ──
    let token_len = recv.read_u32_le().await.context("read token len")?;
    // Cap the declared length BEFORE allocating, so a hostile prefix can't drive a pre-auth OOM.
    if let Err(e) = hb_core::check_token_frame_len(token_len as usize) {
        return send_error(&mut send, &format!("Binding token rejected: {e}")).await;
    }
    let mut token_bytes = vec![0u8; token_len as usize];
    recv.read_exact(&mut token_bytes).await.context("read token")?;
    let token = match hb_core::Token::from_bytes(&token_bytes) {
        Ok(t) => t,
        Err(e) => return send_error(&mut send, &format!("Invalid binding token: {e}")).await,
    };
    let now = unix_now();
    let requester_npub = match hb_core::verify_binding_token(&token, now, TOKEN_MAX_AGE) {
        Ok(npub) => npub,
        Err(e) => return send_error(&mut send, &format!("Binding token rejected: {e}")).await,
    };
    // The (now-authenticated) bound node key must equal the QUIC remote id: a token minted for
    // node A does not authorise a connection from node B.
    match token.node_key() {
        Ok(bound) if &bound == remote_node_key => {}
        Ok(_) => {
            return send_error(&mut send, "Binding token does not match the connecting node").await
        }
        Err(e) => return send_error(&mut send, &format!("Invalid binding token: {e}")).await,
    }

    // ── frame 2: the file request ──
    let req_len = recv.read_u32_le().await.context("read req len")?;
    if let Err(e) = hb_core::check_request_len(req_len as usize) {
        return send_error(&mut send, &format!("Request rejected: {e}")).await;
    }
    let mut req_bytes = vec![0u8; req_len as usize];
    recv.read_exact(&mut req_bytes).await.context("read req")?;
    let req: XferRequest = serde_json::from_slice(&req_bytes).context("parse request")?;

    // M7: validate the remote-supplied slug before it reaches any filesystem path.
    if !crate::commands::collection::is_valid_slug(&req.slug) {
        return send_error(&mut send, "Invalid collection slug").await;
    }

    // Load share settings
    let settings = store
        .load_share_settings(&req.slug)
        .context("load share settings")?
        .unwrap_or_default();

    if !settings.enabled {
        return send_error(&mut send, "Sharing is disabled for this collection").await;
    }

    // H17: gate require_follow on the authenticated npub (not a self-claimed field, not a per-node id).
    if hb_core::follower_gate(settings.require_follow, &follower_npubs(store), &requester_npub)
        .is_err()
    {
        return send_error(&mut send, "This collection is restricted to followers only").await;
    }

    // Enforce download_limit
    if let Some(limit) = settings.download_limit {
        let current = registry.acquire_slot();
        if hb_core::check_download_limit(current, Some(limit)).is_err() {
            registry.release_slot();
            return send_error(&mut send, "Download limit reached — try again later").await;
        }
    }
    // RAII guard to decrement on exit
    let _slot_guard = if settings.download_limit.is_some() {
        Some(DownloadSlotGuard { registry: registry.clone() })
    } else {
        None
    };

    if !is_allowed_path(&req.path, &settings.allowed_paths) {
        return send_error(&mut send, "File is not in the allowed download paths").await;
    }

    let root = match settings.root_path {
        Some(p) => p,
        None => return send_error(&mut send, "Collection root path not configured on sharer's end").await,
    };

    // Build and validate path (prevent traversal)
    let rel = Path::new(&req.path);
    if rel.is_absolute()
        || rel.components().any(|c| c == std::path::Component::ParentDir)
    {
        return send_error(&mut send, "Invalid file path").await;
    }
    let file_path = Path::new(&root).join(rel);

    if !file_path.is_file() {
        return send_error(&mut send, "File not found").await;
    }

    // M8: defense-in-depth against symlink escape. The `..`/absolute check above operates on the
    // unresolved path; resolve symlinks and confirm the real target still lives under the
    // (also-resolved) root. canonicalize() also normalizes Windows UNC `\\?\` prefixes on both
    // sides, so starts_with compares like-for-like.
    let canon_root = tokio::fs::canonicalize(&root)
        .await
        .context("canonicalize share root")?;
    match tokio::fs::canonicalize(&file_path).await {
        Ok(canon_file) if canon_file.starts_with(&canon_root) => {}
        _ => return send_error(&mut send, "Invalid file path").await,
    }

    // Stream file
    let file = tokio::fs::File::open(&file_path).await.context("open file")?;
    let file_size = file.metadata().await.context("metadata")?.len();

    send.write_u8(0).await.context("write ok status")?;
    send.write_u64_le(file_size).await.context("write file size")?;

    let mut reader = tokio::io::BufReader::new(file);

    if let Some(kbps) = settings.speed_cap_kbps {
        throttled_copy(&mut reader, &mut send, kbps as u64 * 1024).await.context("throttled stream")?;
    } else {
        tokio::io::copy(&mut reader, &mut send).await.context("stream file")?;
    }

    send.shutdown().await.context("shutdown send")?;
    Ok(())
}

pub(crate) async fn handle_xfer_connection(
    conn: iroh::endpoint::Connection,
    store: DataStore,
    registry: SharedDownloadRegistry,
) -> Result<()> {
    // The iroh-authenticated identity of the remote peer (its endpoint id, from the QUIC/TLS
    // handshake). The binding token's bound node key is matched against this.
    let remote_node_key: [u8; 32] = *conn.remote_id().as_bytes();
    let (send, recv) = conn.accept_bi().await.context("accept_bi")?;
    let res = handle_xfer_stream(send, recv, &remote_node_key, &store, &registry).await;
    // Hold the connection open until the client has read the response. Small error responses
    // (e.g. the require_follow denial) otherwise race a CONNECTION_CLOSE on fast links and are
    // seen as a truncated read. See conn::drain_connection.
    crate::conn::drain_connection(&conn).await;
    res
}

// ---------------------------------------------------------------------------
// Path matching — glob-aware
// ---------------------------------------------------------------------------

fn is_allowed_path(path: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }

    // Build a glob set from the allowed patterns.
    // Fall back to simple prefix matching if a pattern is not valid glob syntax.
    let mut builder = GlobSetBuilder::new();
    let mut plain_prefixes: Vec<&str> = vec![];

    for pat in allowed {
        let trimmed = pat.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.ends_with('/') {
            plain_prefixes.push(trimmed);
        } else {
            match Glob::new(trimmed) {
                Ok(g) => { builder.add(g); }
                Err(_) => plain_prefixes.push(trimmed),
            }
        }
    }

    // Check plain prefix matches
    for prefix in &plain_prefixes {
        if path.starts_with(prefix) {
            return true;
        }
    }

    // Check glob matches
    if let Ok(set) = builder.build() {
        if set.is_match(path) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Rate-limited copy
// ---------------------------------------------------------------------------

async fn throttled_copy(
    reader: &mut (impl AsyncReadExt + Unpin),
    writer: &mut (impl AsyncWriteExt + Unpin),
    bytes_per_sec: u64,
) -> Result<()> {
    const CHUNK: usize = 65_536; // 64 KB
    let mut buf = vec![0u8; CHUNK];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let start = tokio::time::Instant::now();
        writer.write_all(&buf[..n]).await?;

        // Sleep to hit the target rate.
        let budget = Duration::from_secs_f64(n as f64 / bytes_per_sec as f64);
        let elapsed = start.elapsed();
        if budget > elapsed {
            tokio::time::sleep(budget - elapsed).await;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Download slot RAII guard
// ---------------------------------------------------------------------------

struct DownloadSlotGuard {
    registry: SharedDownloadRegistry,
}

impl Drop for DownloadSlotGuard {
    fn drop(&mut self) {
        self.registry.release_slot();
    }
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

async fn send_error(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    msg: &str,
) -> Result<()> {
    let bytes = msg.as_bytes();
    send.write_u8(1).await.context("write error status")?;
    send.write_u32_le(bytes.len() as u32).await.context("write error len")?;
    send.write_all(bytes).await.context("write error msg")?;
    send.shutdown().await.context("shutdown")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client — called from the request_download command (after H2 resolution)
// ---------------------------------------------------------------------------

/// Connect to a peer and download a single file, emitting progress events. `peer_addr` and
/// `token_bytes` are produced by the caller after H2 binding resolution (see `commands::sharing`):
/// `peer_addr` is built from the node key the peer's *verified presence binding* vouches for, and
/// `token_bytes` is the downloader's own `npub`-signed binding token (the first XFER frame).
#[allow(clippy::too_many_arguments)]
pub async fn download_file(
    endpoint: &Endpoint,
    peer_addr: EndpointAddr,
    token_bytes: Vec<u8>,
    slug: &str,
    path: &str,
    save_path: &str,
    expected_sha256: Option<String>,
    download_id: u64,
    registry: SharedDownloadRegistry,
    app: AppHandle,
) -> Result<u64> {
    download_file_inner(
        endpoint,
        peer_addr,
        token_bytes,
        slug,
        path,
        save_path,
        expected_sha256,
        download_id,
        registry,
        move |ev| { let _ = app.emit("download:progress", ev); },
    )
    .await
}

/// Tauri-free core of [`download_file`]. `on_progress` receives every progress event; the command
/// wrapper forwards them to the webview, while tests and the `hb-p2p-it` harness pass a no-op or
/// logging closure.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_file_inner(
    endpoint: &Endpoint,
    peer_addr: EndpointAddr,
    token_bytes: Vec<u8>,
    slug: &str,
    path: &str,
    save_path: &str,
    expected_sha256: Option<String>,
    download_id: u64,
    registry: SharedDownloadRegistry,
    on_progress: impl Fn(DownloadProgressEvent),
) -> Result<u64> {
    let filename = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string();

    let mut cancel_rx = registry.register(download_id).await;

    let emit_progress = |bytes_done: u64, bytes_total: u64, bps: u64, status: DownloadStatus, error: Option<String>| {
        on_progress(DownloadProgressEvent {
            id: download_id,
            filename: filename.clone(),
            bytes_done,
            bytes_total,
            bytes_per_sec: bps,
            status,
            error,
        });
    };

    emit_progress(0, 0, 0, DownloadStatus::Active, None);

    let conn = endpoint
        .connect(peer_addr, XFER_ALPN)
        .await
        .context("connect to peer")?;

    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;

    // H17 frame 1: our binding token, then frame 2: the file request.
    send.write_u32_le(token_bytes.len() as u32).await.context("write token len")?;
    send.write_all(&token_bytes).await.context("write token")?;

    let req = XferRequest { slug: slug.to_string(), path: path.to_string() };
    let req_bytes = serde_json::to_vec(&req).context("serialize request")?;
    send.write_u32_le(req_bytes.len() as u32).await.context("write req len")?;
    send.write_all(&req_bytes).await.context("write req")?;
    send.shutdown().await.context("shutdown send")?;

    let status = recv.read_u8().await.context("read status")?;
    if status != 0 {
        let err_len = recv.read_u32_le().await.context("read err len")?;
        let mut err_bytes = vec![0u8; err_len as usize];
        recv.read_exact(&mut err_bytes).await.context("read err")?;
        let msg = String::from_utf8_lossy(&err_bytes).into_owned();
        emit_progress(0, 0, 0, DownloadStatus::Error, Some(msg.clone()));
        registry.remove(download_id).await;
        return Err(anyhow!(msg));
    }

    let file_size = recv.read_u64_le().await.context("read file size")?;
    emit_progress(0, file_size, 0, DownloadStatus::Active, None);

    if let Some(parent) = Path::new(save_path).parent() {
        tokio::fs::create_dir_all(parent).await.context("create dirs")?;
    }
    let out = tokio::fs::File::create(save_path).await.context("create output file")?;
    let mut writer = tokio::io::BufWriter::new(out);

    // Chunked copy with progress emission every ~250 KB, cancel check per chunk.
    const CHUNK: usize = 256 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut bytes_done: u64 = 0;
    let start = Instant::now();
    let mut last_emit = Instant::now();

    loop {
        // Cancel check
        if cancel_rx.try_recv().is_ok() {
            drop(writer);
            let _ = tokio::fs::remove_file(save_path).await;
            emit_progress(bytes_done, file_size, 0, DownloadStatus::Cancelled, None);
            registry.remove(download_id).await;
            conn.close(0u32.into(), b"cancelled");
            return Err(anyhow!("Download cancelled"));
        }

        let remaining = (file_size - bytes_done) as usize;
        if remaining == 0 { break; }
        let to_read = remaining.min(CHUNK);
        // Quinn-style read returns Option<usize> — None means stream ended.
        let n = match recv.read(&mut buf[..to_read]).await.context("read chunk")? {
            Some(n) => n,
            None => break,
        };
        if n == 0 { break; }

        writer.write_all(&buf[..n]).await.context("write chunk")?;
        bytes_done += n as u64;

        // Emit every 250 ms
        if last_emit.elapsed().as_millis() >= 250 {
            let elapsed_secs = start.elapsed().as_secs_f64().max(0.001);
            let bps = (bytes_done as f64 / elapsed_secs) as u64;
            emit_progress(bytes_done, file_size, bps, DownloadStatus::Active, None);
            last_emit = Instant::now();
        }
    }

    writer.flush().await.context("flush")?;

    if let Some(ref expected) = expected_sha256 {
        let written = tokio::fs::read(save_path).await.context("re-read for integrity check")?;
        if let Err(e) = verify_hash(&written, expected) {
            let _ = tokio::fs::remove_file(save_path).await;
            let msg = format!("Integrity check failed: {e}");
            emit_progress(bytes_done, file_size, 0, DownloadStatus::Error, Some(msg.clone()));
            registry.remove(download_id).await;
            conn.close(0u32.into(), b"hash-mismatch");
            return Err(anyhow!(msg));
        }
    }

    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let bps = (bytes_done as f64 / elapsed) as u64;
    emit_progress(bytes_done, file_size, bps, DownloadStatus::Done, None);
    registry.remove(download_id).await;
    conn.close(0u32.into(), b"");
    Ok(bytes_done)
}

/// Build the requester's binding-token wire frame: an `npub`-signed token over `own_node_key`,
/// stamped now. The H2-resolved peer address + this token are the two inputs `download_file` needs.
pub(crate) fn build_token_frame(
    identity: &hb_core::Identity,
    own_node_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let token = hb_core::build_binding_token(identity, own_node_key, unix_now())
        .map_err(|e| anyhow!("build binding token: {e}"))?;
    Ok(token.to_bytes())
}

/// Resolve a peer's dialable [`EndpointAddr`] from their **verified** presence binding (H2): the
/// node key is taken from the binding (not a relay-supplied address), and the transport addresses
/// are unsealed from the binding under the peer's browse-key. A relay that serves a forged/expired
/// binding, or a missing/locked sealed address, yields a reasoned `Err` — never a dial.
pub(crate) fn resolve_peer_addr(
    presence: &nostr::Event,
    peer_npub: &nostr::PublicKey,
    peer_browse_key: &hb_core::BrowseKey,
) -> Result<EndpointAddr> {
    let now = unix_now();
    let binding = hb_core::verify_binding(presence, peer_npub, now)
        .map_err(|e| anyhow!("peer presence binding rejected: {e}"))?;
    let addrs = binding
        .addr
        .unseal(peer_browse_key)
        .map_err(|e| anyhow!("no reachable address for peer: {e}"))?;
    let raw = addrs
        .first()
        .ok_or_else(|| anyhow!("peer advertised no transport address"))?;
    // The sealed payload is the peer's serialized iroh EndpointAddr (id + transport addrs).
    let endpoint_addr: EndpointAddr =
        serde_json::from_str(raw).context("parse sealed peer EndpointAddr")?;
    // Defense-in-depth: the dialed node id must equal the node key the signed binding vouches for.
    if *endpoint_addr.id.as_bytes() != binding.node_key {
        return Err(anyhow!(
            "peer's sealed address does not match the node key its binding vouches for — refusing to connect"
        ));
    }
    Ok(endpoint_addr)
}

// ---------------------------------------------------------------------------
// Integrity helpers
// ---------------------------------------------------------------------------

pub(crate) fn sha256_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Return `Ok(())` if `data` hashes to `expected_hex`; `Err` otherwise.
pub(crate) fn verify_hash(data: &[u8], expected_hex: &str) -> anyhow::Result<()> {
    let actual = sha256_bytes(data);
    anyhow::ensure!(
        actual == expected_hex,
        "SHA256 mismatch: got {actual}, expected {expected_hex}"
    );
    Ok(())
}

/// Build the npub of a public key (used by tests + callers needing the bech32 form).
#[allow(dead_code)]
fn npub_of(pk: &nostr::PublicKey) -> String {
    pk.to_bech32().unwrap_or_else(|_| pk.to_hex())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CachedPeer, DataStore, ShareSettings};
    use hb_core::Identity;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn node_key() -> [u8; 32] {
        rand::random()
    }

    /// Write a valid binding token + request frame to `cli_w`, returning nothing.
    async fn write_token_and_request<W: AsyncWriteExt + Unpin>(
        cli_w: &mut W,
        requester: &Identity,
        requester_node: &[u8; 32],
        slug: &str,
        path: &str,
    ) {
        let token =
            hb_core::build_binding_token(requester, requester_node, unix_now()).unwrap();
        let tb = token.to_bytes();
        cli_w.write_u32_le(tb.len() as u32).await.unwrap();
        cli_w.write_all(&tb).await.unwrap();
        let req = serde_json::to_vec(&serde_json::json!({"slug": slug, "path": path})).unwrap();
        cli_w.write_u32_le(req.len() as u32).await.unwrap();
        cli_w.write_all(&req).await.unwrap();
        cli_w.shutdown().await.unwrap();
    }

    async fn read_error<R: AsyncReadExt + Unpin>(cli_r: &mut R) -> String {
        let status = cli_r.read_u8().await.unwrap();
        assert_eq!(status, 1, "expected an error status byte");
        let elen = cli_r.read_u32_le().await.unwrap();
        let mut ebuf = vec![0u8; elen as usize];
        cli_r.read_exact(&mut ebuf).await.unwrap();
        String::from_utf8(ebuf).unwrap()
    }

    fn save_contact(store: &DataStore, npub: &str) {
        store
            .save_contact(
                &CachedPeer::pubkey_hash(npub),
                &CachedPeer {
                    npub: npub.to_string(),
                    browse_key_hex: None,
                    petname: None,
                    profile: None,
                    collections: vec![],
                    online: false,
                    last_fetched: chrono::Utc::now(),
                    local_tags: vec![],
                },
            )
            .unwrap();
    }

    #[test]
    fn glob_pattern_matches_extension() {
        assert!(is_allowed_path("Movies/Akira.mkv", &["**/*.mkv".to_string()]));
        assert!(is_allowed_path("Season 1/E01.mkv", &["Season 1/**".to_string()]));
        assert!(!is_allowed_path("Season 2/E01.mkv", &["Season 1/**".to_string()]));
        assert!(is_allowed_path("anything", &[]));
    }

    #[test]
    fn prefix_matching_still_works() {
        assert!(is_allowed_path("Movies/foo.mp4", &["Movies/".to_string()]));
        assert!(!is_allowed_path("Other/foo.mp4", &["Movies/".to_string()]));
    }

    #[test]
    fn verify_hash_accepts_matching_content() {
        let data = b"some file content";
        let hash = sha256_bytes(data);
        assert!(verify_hash(data, &hash).is_ok());
    }

    #[test]
    fn verify_hash_rejects_corrupted_content() {
        let hash = sha256_bytes(b"original");
        assert!(verify_hash(b"corrupted", &hash).is_err());
    }

    // ── H17: the binding gate over the wire (duplex, no QUIC) ──────────────────

    #[tokio::test]
    async fn xfer_stream_invalid_slug_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = DataStore::new(dir.path().to_path_buf());
        let registry = std::sync::Arc::new(DownloadRegistry::new());

        let requester = Identity::generate();
        let rnode = node_key();

        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (mut cli_r, mut cli_w) = tokio::io::split(cli);
        let (srv_r, srv_w) = tokio::io::split(srv);
        tokio::spawn(async move {
            let _ = handle_xfer_stream(srv_w, srv_r, &rnode, &store, &registry).await;
        });

        write_token_and_request(&mut cli_w, &requester, &rnode, "../etc/passwd", "f.txt").await;
        let msg = read_error(&mut cli_r).await;
        assert!(msg.contains("Invalid collection slug"), "got: {msg}");
    }

    #[tokio::test]
    async fn xfer_stream_require_follow_blocks_stranger() {
        let dir = tempfile::tempdir().unwrap();
        let store = DataStore::new(dir.path().to_path_buf());
        store.save_share_settings("col", &ShareSettings {
            enabled: true, require_follow: true,
            root_path: Some(dir.path().to_str().unwrap().to_string()),
            ..Default::default()
        }).unwrap();

        let stranger = Identity::generate();
        let rnode = node_key();
        let registry = std::sync::Arc::new(DownloadRegistry::new());
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (mut cli_r, mut cli_w) = tokio::io::split(cli);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let s2 = store.clone();
        tokio::spawn(async move {
            let _ = handle_xfer_stream(srv_w, srv_r, &rnode, &s2, &registry).await;
        });

        write_token_and_request(&mut cli_w, &stranger, &rnode, "col", "f.txt").await;
        let msg = read_error(&mut cli_r).await;
        assert!(msg.contains("restricted to followers"), "got: {msg}");
    }

    #[tokio::test]
    async fn xfer_stream_require_follow_allows_contact() {
        let dir = tempfile::tempdir().unwrap();
        let store = DataStore::new(dir.path().to_path_buf());
        store.save_share_settings("col", &ShareSettings {
            enabled: true, require_follow: true,
            root_path: Some(dir.path().to_str().unwrap().to_string()),
            ..Default::default()
        }).unwrap();

        let peer = Identity::generate();
        save_contact(&store, &peer.npub()); // npub is a follower
        let rnode = node_key();
        let registry = std::sync::Arc::new(DownloadRegistry::new());
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (mut cli_r, mut cli_w) = tokio::io::split(cli);
        let (srv_r, srv_w) = tokio::io::split(srv);
        let s2 = store.clone();
        tokio::spawn(async move {
            let _ = handle_xfer_stream(srv_w, srv_r, &rnode, &s2, &registry).await;
        });

        write_token_and_request(&mut cli_w, &peer, &rnode, "col", "f.txt").await;
        let msg = read_error(&mut cli_r).await;
        // Passed the follower gate; the next failure is "File not found", not the gate.
        assert!(!msg.contains("restricted to followers"), "contact must pass; got: {msg}");
    }

    #[tokio::test]
    async fn xfer_stream_rejects_token_for_a_different_node() {
        // AB4: a token bound to node A presented on a connection from node B is refused — the
        // bound node key must match conn.remote_id().
        let dir = tempfile::tempdir().unwrap();
        let store = DataStore::new(dir.path().to_path_buf());
        store.save_share_settings("col", &ShareSettings {
            enabled: true, root_path: Some(dir.path().to_str().unwrap().to_string()),
            ..Default::default()
        }).unwrap();

        let requester = Identity::generate();
        let token_node = node_key();      // token is minted for this node
        let connecting_node = node_key(); // but the connection is from a different node
        let registry = std::sync::Arc::new(DownloadRegistry::new());
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (mut cli_r, mut cli_w) = tokio::io::split(cli);
        let (srv_r, srv_w) = tokio::io::split(srv);
        tokio::spawn(async move {
            let _ = handle_xfer_stream(srv_w, srv_r, &connecting_node, &store, &registry).await;
        });

        // Token bound to token_node, but server sees connecting_node as the remote.
        write_token_and_request(&mut cli_w, &requester, &token_node, "col", "f.txt").await;
        let msg = read_error(&mut cli_r).await;
        assert!(msg.contains("does not match the connecting node"), "got: {msg}");
    }

    #[tokio::test]
    async fn xfer_stream_rejects_oversize_token_frame() {
        // AB7: a hostile token-frame length prefix beyond the cap is refused before any allocation.
        let dir = tempfile::tempdir().unwrap();
        let store = DataStore::new(dir.path().to_path_buf());
        let rnode = node_key();
        let registry = std::sync::Arc::new(DownloadRegistry::new());
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (mut cli_r, mut cli_w) = tokio::io::split(cli);
        let (srv_r, srv_w) = tokio::io::split(srv);
        tokio::spawn(async move {
            let _ = handle_xfer_stream(srv_w, srv_r, &rnode, &store, &registry).await;
        });

        // Declare a token length far past the 8 KiB cap; never send the bytes.
        cli_w.write_u32_le((hb_core::MAX_TOKEN_FRAME_BYTES as u32) + 1).await.unwrap();
        cli_w.flush().await.unwrap();
        let msg = read_error(&mut cli_r).await;
        assert!(msg.contains("Binding token rejected"), "got: {msg}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn xfer_stream_symlink_escape_rejected() {
        use std::os::unix::fs::symlink;

        let outer = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let db = tempfile::tempdir().unwrap();

        let secret = outer.path().join("secret.txt");
        std::fs::write(&secret, b"secret content").unwrap();
        symlink(&secret, root.path().join("escape.txt")).unwrap();

        let store = DataStore::new(db.path().to_path_buf());
        store.save_share_settings("col", &ShareSettings {
            enabled: true,
            root_path: Some(root.path().to_str().unwrap().to_string()),
            ..Default::default()
        }).unwrap();

        let requester = Identity::generate();
        let rnode = node_key();
        let registry = std::sync::Arc::new(DownloadRegistry::new());
        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let (mut cli_r, mut cli_w) = tokio::io::split(cli);
        let (srv_r, srv_w) = tokio::io::split(srv);
        tokio::spawn(async move {
            let _ = handle_xfer_stream(srv_w, srv_r, &rnode, &store, &registry).await;
        });

        write_token_and_request(&mut cli_w, &requester, &rnode, "col", "escape.txt").await;
        let msg = read_error(&mut cli_r).await;
        assert!(msg.contains("Invalid file path"), "symlink escape must be rejected; got: {msg}");
    }
}
