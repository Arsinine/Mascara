//! The `serve` accept loop and the `/mascara/xfer/1` server side (DESIGN §4). Mining map: the
//! quarry's `handle_xfer_stream` skeleton (length-cap-before-alloc, `send_error`) → here, auth
//! swapped from the H17 token frame to nonce + `conn.remote_id()`; the quarry's `conn.rs` drain
//! helper → [`drain`], as-is.
//!
//! **The auth predicate is a pure function** ([`authorize`]) over a registry snapshot — no I/O, no
//! iroh — so DESIGN §4's ordering (revocation/expiry BEFORE the identity comparison, so a revoked
//! ticket and a stranger are refused identically) is unit-testable without any network. The
//! per-stream protocol handler ([`handle_request`]) is written against generic
//! `AsyncRead+AsyncWrite`, so the exact same logic runs over `tokio::io::duplex` in tests and a
//! real iroh stream in production; only [`run`] (the accept loop) and the drain helper touch iroh.
//!
//! **Where do the bytes live?** `mascara-core`'s `issued.json` registry (MR-8) deliberately never
//! stores a ticket's local file path, `file_ref`, or `grant` — only what the auth predicate needs.
//! Something must still answer "where is nonce N's file on THIS disk" for `serve` to work at all;
//! that is [`OfferRecord`]/[`OfferStore`] — local-only, unsealed, host-side bookkeeping written by
//! `mascara send` at issue time and read by `serve` at request time. It is deliberately NOT part
//! of `mascara-core` (kept out of the sealed ticket and the portable registry state) — see the M2
//! HANDOVER note on this deviation from the brief's literal CLI surface.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use mascara_core::{
    decode_and_verify_manifest, FileRef, FolderRef, Grant, IssuedStore, IssuedTickets,
    ManifestEntry, Nonce, Payload, SourceCheck, MANIFEST_HARD_CAP_BYTES,
};

use crate::error::NetError;

/// Request frame length cap (DESIGN §4) — checked BEFORE allocating the buffer.
pub const MAX_REQUEST_FRAME: usize = 8 * 1024;

/// Cap on the manifest body the server reads back from its own store before serving (mirrors
/// `mascara_core::MANIFEST_HARD_CAP_BYTES`). The wire framing writes this as `u64-LE total`; the
/// client refuses `total > 32 MiB` before allocating (DESIGN §4, chorus H4).
pub const MAX_MANIFEST_FRAME: usize = MANIFEST_HARD_CAP_BYTES;

// --------------------------------------------------------------------------------------------
// The auth predicate (DESIGN §4) — pure, unit-testable without I/O or iroh.
// --------------------------------------------------------------------------------------------

/// Why a request was refused, evaluated in the DESIGN §4 order. Revocation/expiry (folded into
/// `IssuedTickets::is_valid`) are checked BEFORE the identity comparison, so a revoked/expired/
/// unknown ticket and a stranger presenting someone else's nonce get the *same* refusal class —
/// `sem_auth_not_nonce_secrecy`: a valid nonce is an identifier, not proof of authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Unknown, revoked, or expired nonce.
    InvalidTicket,
    /// The nonce is valid and active, but this connection is not the recipient it was sealed to.
    WrongRemote,
    /// A `sync` grant, recognised and refused in Phase 1 (D18).
    SyncNotSupported,
    /// No local source is registered for this (otherwise-valid) nonce.
    NoLocalSource,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::InvalidTicket => "this ticket is unknown, revoked, or expired",
            Refusal::WrongRemote => "this ticket was not sealed to your endpoint",
            Refusal::SyncNotSupported => {
                "sync-grant tickets are not supported yet (Phase 1 is download-only)"
            }
            Refusal::NoLocalSource => "no local source is registered for this ticket",
        })
    }
}

/// The DESIGN §4 auth predicate's identity half: `nonce ∈ issued ∧ ∉ revoked ∧ unexpired ∧
/// conn.remote_id() == the transport key the nonce was sealed to`. Pure over a registry snapshot.
pub fn authorize(
    tickets: &IssuedTickets,
    nonce: &Nonce,
    remote_id: [u8; 32],
    now: DateTime<Utc>,
) -> Result<(), Refusal> {
    if !tickets.is_valid(nonce, now) {
        return Err(Refusal::InvalidTicket);
    }
    // `is_valid` true ⇒ a matching, active record exists, and MR-8 keeps its recipient `Some`
    // while active — so this is always populated here.
    let recipient = tickets.tickets.iter().find(|r| &r.nonce == nonce).and_then(|r| r.recipient_transport_pk);
    if recipient != Some(remote_id) {
        return Err(Refusal::WrongRemote);
    }
    Ok(())
}

// --------------------------------------------------------------------------------------------
// OfferRecord / OfferStore — local-only "where do my bytes live" bookkeeping (see module docs).
// --------------------------------------------------------------------------------------------

/// The payload half of [`OfferRecord`], mirroring core's [`Payload`]: the file form keeps the M2
/// `{path, file_ref}`; the folder form carries `{dir_path, folder_ref, manifest_path}` where
/// `manifest_path` is the sender-side stored manifest bytes (`<home>/manifests/<nonce-hex>.postcard`)
/// — written once at record time so the bytes served are byte-identical to what `root_hash`
/// commits to (chorus H4 — the manifest is served, not re-encoded).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum OfferPayload {
    File { path: PathBuf, file_ref: FileRef },
    Folder { dir_path: PathBuf, folder_ref: FolderRef, manifest_path: PathBuf },
}

impl OfferPayload {
    /// The kind discriminant, for the file/folder branch in [`handle_request`].
    pub fn kind(&self) -> Payload {
        match self {
            OfferPayload::File { file_ref, .. } => Payload::File(file_ref.clone()),
            OfferPayload::Folder { folder_ref, .. } => Payload::Folder(folder_ref.clone()),
        }
    }
}

/// One nonce this device can currently serve: the nonce, its `grant` (so a `sync` ticket is
/// recognised and refused even though the registry carries no grant), and the kind-specific
/// payload — the local file path + `file_ref` (file form), or the dir + `folder_ref` + stored
/// manifest path (folder form). Local-only, never sealed, never sent.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OfferRecord {
    pub nonce: Nonce,
    pub payload: OfferPayload,
    pub grant: Grant,
}

const OFFERS_FILE: &str = "offers.json";
/// Bumped at M3 stage 3: the payload is now a `kind`-tagged enum, not the flat file form. A
/// future reader seeing v1 treats it as unreadable (reasoned refusal) rather than guessing.
const OFFERS_VERSION: u8 = 2;

#[derive(Serialize, Deserialize)]
struct OfferFile {
    v: u8,
    entries: Vec<OfferRecord>,
}

impl Default for OfferFile {
    fn default() -> Self {
        OfferFile { v: OFFERS_VERSION, entries: Vec::new() }
    }
}

/// File-backed store for `OfferRecord`s: `<home>/tickets/offers.json`, atomic tmp+rename writes
/// (mirrors `mascara-core::registry`'s discipline). The folder form carries a `manifest_path` into
/// `<home>/manifests/<nonce-hex>.postcard` (DESIGN §7) — the bytes served byte-identical to what
/// `folder_ref.root_hash` commits to, stored atomically at record time by [`Self::record_folder`].
pub struct OfferStore {
    path: PathBuf,
    home: PathBuf,
}

impl OfferStore {
    pub fn at(home: &Path) -> Self {
        OfferStore { path: home.join("tickets").join(OFFERS_FILE), home: home.to_path_buf() }
    }

    /// `<home>/manifests/<nonce-hex>.postcard` — the sender-side cache of the manifest bytes,
    /// written once at record time and read back (and re-verified) on every manifest op.
    pub fn manifest_path_for(&self, nonce: &Nonce) -> PathBuf {
        self.home.join("manifests").join(format!("{}.postcard", nonce.to_hex()))
    }

    fn load(&self) -> Result<OfferFile, NetError> {
        if !self.path.is_file() {
            return Ok(OfferFile::default());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        let parsed: OfferFile = serde_json::from_str(&raw)
            .map_err(|e| NetError::Protocol(format!("malformed {OFFERS_FILE}: {e}")))?;
        if parsed.v != OFFERS_VERSION {
            return Err(NetError::Protocol(format!(
                "unsupported {OFFERS_FILE} version {} (this Mascara understands v{OFFERS_VERSION})",
                parsed.v
            )));
        }
        Ok(parsed)
    }

    fn store(&self, file: &OfferFile) -> Result<(), NetError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(file)
            .map_err(|e| NetError::Protocol(format!("could not encode {OFFERS_FILE}: {e}")))?;
        atomic_write(&self.path, json.as_bytes())
    }

    /// Record (or replace) the local serve facts for `record.nonce` — called by `mascara send` at
    /// issue time. The M2-era flat file form has been replaced by the v2 `OfferPayload` enum; new
    /// callers should use [`Self::record_file`] / [`Self::record_folder`].
    pub fn record(&self, record: OfferRecord) -> Result<(), NetError> {
        let mut f = self.load()?;
        f.entries.retain(|r| r.nonce != record.nonce);
        f.entries.push(record);
        self.store(&f)
    }

    /// Record a FILE offer: the local source path + the ticket's `file_ref` + grant.
    pub fn record_file(
        &self,
        nonce: Nonce,
        path: PathBuf,
        file_ref: FileRef,
        grant: Grant,
    ) -> Result<(), NetError> {
        self.record(OfferRecord {
            nonce,
            payload: OfferPayload::File { path, file_ref },
            grant,
        })
    }

    /// Record a FOLDER offer: the local source dir, the ticket's `folder_ref`, and the manifest
    /// bytes (stored atomically under `<home>/manifests/<nonce-hex>.postcard`, DESIGN §7). The
    /// manifest bytes are served byte-identical to what `folder_ref.root_hash` commits to; this
    /// helper re-verifies `sha256(bytes) == folder_ref.root_hash` before recording, so a tampered
    /// store is caught at record time too (defense in depth — `handle_request` re-verifies on
    /// every read).
    pub fn record_folder(
        &self,
        nonce: Nonce,
        dir_path: PathBuf,
        folder_ref: FolderRef,
        manifest_bytes: Vec<u8>,
        grant: Grant,
    ) -> Result<(), NetError> {
        // The sender-side consistency check: the bytes hash to what the ticket commits to. The
        // CLI's descriptor path already ran `verify_root_hash`; this re-check guards against a
        // caller passing mismatched bytes (defense in depth, mirror of the receive-side gate).
        let actual: [u8; 32] = Sha256::digest(&manifest_bytes).into();
        if actual != folder_ref.root_hash {
            return Err(NetError::Protocol(format!(
                "manifest bytes do not match folder_ref.root_hash (expected {}, got {}) — refusing \
                 to record a folder offer whose stored bytes would not verify",
                hex::encode(folder_ref.root_hash),
                hex::encode(actual),
            )));
        }
        let manifest_path = self.manifest_path_for(&nonce);
        if let Some(dir) = manifest_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        atomic_write(&manifest_path, &manifest_bytes)?;
        self.record(OfferRecord {
            nonce,
            payload: OfferPayload::Folder { dir_path, folder_ref, manifest_path },
            grant,
        })
    }

    /// Look up the local serve facts for `nonce`, if this device has any recorded.
    pub fn find(&self, nonce: &Nonce) -> Result<Option<OfferRecord>, NetError> {
        Ok(self.load()?.entries.into_iter().find(|r| &r.nonce == nonce))
    }
}

/// Atomic tmp+rename write (mirrors `mascara-core::registry`'s discipline). The temp file's name
/// is derived from the target's file name + a random suffix, so concurrent writes to different
/// targets don't collide and a crash never leaves a torn target.
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

// --------------------------------------------------------------------------------------------
// Unknown-remote rate cap — the DESIGN §4 DoS floor for the connection-level pre-filter.
// --------------------------------------------------------------------------------------------

/// Caps how many connection attempts an unrecognised remote may make per window before [`run`]
/// stops even accepting a stream from it. Pure and unit-testable; a resource floor, not a full
/// rate-limiter (Suite NET's fuller enforcement lands M4).
pub struct UnknownRemoteLimiter {
    window: Duration,
    max_per_window: u32,
    seen: Mutex<HashMap<[u8; 32], (Instant, u32)>>,
}

impl UnknownRemoteLimiter {
    pub fn new(window: Duration, max_per_window: u32) -> Self {
        UnknownRemoteLimiter { window, max_per_window, seen: Mutex::new(HashMap::new()) }
    }

    /// The M2 default: 20 attempts per 60-second window per unknown remote.
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(60), 20)
    }

    /// Record an attempt from `remote`; `true` if still under the cap (allow), `false` if capped.
    pub fn allow(&self, remote: [u8; 32]) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let entry = seen.entry(remote).or_insert((now, 0));
        if now.duration_since(entry.0) > self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max_per_window
    }
}

// --------------------------------------------------------------------------------------------
// Wire framing (DESIGN §4).
// --------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub(crate) struct Request {
    pub(crate) v: u8,
    pub(crate) nonce: Nonce,
    pub(crate) op: Op,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Op {
    Manifest,
    File { path: String, offset: u64 },
}

async fn send_error(send: &mut (impl AsyncWrite + Unpin), msg: &str) -> Result<(), NetError> {
    let bytes = msg.as_bytes();
    send.write_u8(1).await?;
    send.write_u32_le(bytes.len() as u32).await?;
    send.write_all(bytes).await?;
    send.shutdown().await?;
    Ok(())
}

/// Resolve a manifest-relative path strictly beneath a folder offer's `dir_path`, with the quarry's
/// M8 canonicalize + symlink-escape defense-in-depth (DESIGN §4 / §9): the `..`/absolute check
/// operates on the *unresolved* path; resolve symlinks on both sides and confirm the real target
/// still lives under the (also-resolved) root. `canonicalize` normalizes Windows UNC `\\?\`
/// prefixes on both sides so `starts_with` compares like-for-like. Returns the resolved file path
/// on success; a reasoned refusal string on any escape attempt.
///
/// Synchronous because `canonicalize` is — and `handle_request`'s one `tokio::fs` op (the actual
/// file open) follows this and stays async.
fn resolve_within_root(dir_path: &Path, rel: &str) -> Result<PathBuf, String> {
    let parsed = Path::new(rel);
    if rel.is_empty()
        || parsed.is_absolute()
        || parsed
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::RootDir))
    {
        return Err(format!(
            "the requested path {rel:?} is not a plain path inside the shared folder (empty, absolute, or contains '..')"
        ));
    }
    let file_path = dir_path.join(parsed);
    // M8: canonicalize both sides and confirm the real target still lives under the root — a
    // symlink planted inside the shared dir must not escape it. (Unix `canonicalize` follows
    // symlinks; Windows resolves them and strips the `\\?\` prefix consistently on both sides.)
    let canon_root = std::fs::canonicalize(dir_path)
        .map_err(|e| format!("could not resolve the shared folder root: {e}"))?;
    match std::fs::canonicalize(&file_path) {
        Ok(canon_file) if canon_file.starts_with(&canon_root) => Ok(canon_file),
        _ => Err(format!(
            "the requested path {rel:?} resolves outside the shared folder (symlink escape refused)"
        )),
    }
}

/// Read a stored manifest file, **checking its size via metadata BEFORE allocating** (codex #3).
/// `fs::read` sizes its buffer from the file itself, so a stored manifest swapped for a multi-GiB
/// file would be fully allocated before any cap check could reject it. The cap is
/// [`MAX_MANIFEST_FRAME`]; over it is a reasoned error and nothing is read.
async fn read_stored_manifest(manifest_path: &Path) -> Result<Vec<u8>, NetError> {
    let meta = tokio::fs::metadata(manifest_path).await?;
    if meta.len() > MAX_MANIFEST_FRAME as u64 {
        return Err(NetError::Protocol(format!(
            "the stored manifest is {} bytes — over the {MAX_MANIFEST_FRAME} cap; refusing to read it",
            meta.len()
        )));
    }
    Ok(tokio::fs::read(manifest_path).await?)
}

/// Look up a single manifest entry by `rel_path` — a folder `file` op must serve a path *in the
/// committed manifest*, not just any file under the sender's dir. Returns the entry on success; a
/// reasoned refusal string otherwise.
fn manifest_entry_for<'a>(entries: &'a [ManifestEntry], rel_path: &str) -> Result<&'a ManifestEntry, String> {
    entries
        .iter()
        .find(|e| e.rel_path == rel_path)
        .ok_or_else(|| format!("the requested path {rel_path:?} is not an entry in this folder's manifest"))
}

/// Handle one request/response over an already-open bi-stream (DESIGN §4). Generic over
/// `AsyncRead+AsyncWrite`, so the same logic runs over `tokio::io::duplex` in tests and a real
/// iroh stream in production.
///
/// `remote_id` is the QUIC-authenticated peer identity (`conn.remote_id()`) — the only
/// trustworthy claim of who is asking. `tickets` should be a **freshly loaded** registry snapshot
/// (re-read from disk per request by the caller, so a revocation during `serve` takes effect
/// immediately). `lookup_offer` resolves a nonce to this device's local serve facts.
///
/// Folder flow (M3 stage 3, DESIGN §4):
/// - `Op::Manifest` on a folder offer → load the stored manifest bytes, **re-verify
///   `sha256(bytes) == folder_ref.root_hash`** (the sender's own store could have been tampered),
///   then serve them byte-identical behind the u64-LE total, capped at 32 MiB.
/// - `Op::File { path, offset }` on a folder offer → the `path` must be an entry in the committed
///   manifest (loaded + verified first), resolved strictly beneath `dir_path` via
///   [`resolve_within_root`], with the per-file [`check_source`] run against the entry's own size.
///
/// Returns `Ok(())` whether the request succeeded OR was refused with a reasoned error response —
/// both are "handled". `Err` means the stream itself broke (a real I/O/transport failure).
pub async fn handle_request(
    mut send: impl AsyncWrite + Unpin,
    mut recv: impl AsyncRead + Unpin,
    remote_id: [u8; 32],
    tickets: &IssuedTickets,
    lookup_offer: impl Fn(&Nonce) -> Option<OfferRecord>,
    now: DateTime<Utc>,
) -> Result<(), NetError> {
    let len = recv.read_u32_le().await?;
    if len as usize > MAX_REQUEST_FRAME {
        return send_error(
            &mut send,
            &format!("request frame too large ({len} bytes, cap {MAX_REQUEST_FRAME} bytes)"),
        )
        .await;
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await?;
    let req: Request = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => return send_error(&mut send, &format!("malformed request: {e}")).await,
    };
    if req.v != 1 {
        return send_error(&mut send, &format!("unsupported protocol version {}", req.v)).await;
    }

    if let Err(refusal) = authorize(tickets, &req.nonce, remote_id, now) {
        return send_error(&mut send, &refusal.to_string()).await;
    }

    let offer = match lookup_offer(&req.nonce) {
        Some(o) => o,
        None => return send_error(&mut send, &Refusal::NoLocalSource.to_string()).await,
    };
    if offer.grant != Grant::Download {
        return send_error(&mut send, &Refusal::SyncNotSupported.to_string()).await;
    }

    match (&offer.payload, req.op) {
        (OfferPayload::File { path, file_ref }, Op::File { path: req_path, offset }) => {
            // The single-file ticket's path is fixed: the request must name exactly it.
            if req_path != file_ref.name {
                return send_error(
                    &mut send,
                    "the requested path does not match this ticket's file",
                )
                .await;
            }
            serve_file_op(&mut send, path, file_ref, offset).await
        }
        (OfferPayload::File { .. }, Op::Manifest) => {
            send_error(&mut send, "this is a file ticket; a manifest op applies only to folder tickets")
                .await
        }
        (OfferPayload::Folder { folder_ref, manifest_path, .. }, Op::Manifest) => {
            serve_manifest_op(&mut send, manifest_path, folder_ref).await
        }
        (
            OfferPayload::Folder { dir_path, folder_ref, manifest_path },
            Op::File { path: rel_path, offset },
        ) => {
            serve_folder_file_op(&mut send, dir_path, folder_ref, manifest_path, &rel_path, offset)
                .await
        }
    }
}

/// Serve a `file` op against a FILE offer (the M2 path, now behind the v2 dispatch).
async fn serve_file_op(
    send: &mut (impl AsyncWrite + Unpin),
    path: &Path,
    file_ref: &FileRef,
    offset: u64,
) -> Result<(), NetError> {
    match mascara_core::check_source(path, file_ref) {
        SourceCheck::Missing => {
            return send_error(
                send,
                "the source file is no longer present on the sender's device",
            )
            .await
        }
        SourceCheck::Changed { expected, actual } => {
            return send_error(
                send,
                &format!(
                    "the source file changed since the ticket was issued (was {expected} bytes, now {actual})"
                ),
            )
            .await
        }
        SourceCheck::Ok => {}
    }
    stream_file(send, path, file_ref.size, offset).await
}

/// Serve a `manifest` op against a FOLDER offer: load the stored bytes, **re-verify
/// `sha256(bytes) == folder_ref.root_hash`** (chorus H4 — never serve a manifest whose stored
/// bytes drifted from the commitment; the sender's own store could have been tampered), then write
/// `[u8 status=0][u64-LE total][manifest bytes]` (DESIGN §4). `total` is bounded by
/// [`MAX_MANIFEST_FRAME`].
async fn serve_manifest_op(
    send: &mut (impl AsyncWrite + Unpin),
    manifest_path: &Path,
    folder_ref: &FolderRef,
) -> Result<(), NetError> {
    let bytes = read_stored_manifest(manifest_path).await?;
    // Re-verify against the ticket's commitment on every read — defense in depth.
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != folder_ref.root_hash {
        return send_error(
            send,
            &format!(
                "the sender's stored manifest no longer matches the ticket's root_hash (expected {}, \
                 got {}) — refusing to serve a manifest that would not verify on the receiver",
                hex::encode(folder_ref.root_hash),
                hex::encode(actual)
            ),
        )
        .await;
    }
    // The client refuses total > MAX_MANIFEST_FRAME before allocating; assert it here too so a
    // future record bug that wrote an over-cap file fails closed on the sender side.
    if bytes.len() > MAX_MANIFEST_FRAME {
        return send_error(
            send,
            &format!(
                "the folder manifest is {} bytes — over the {} cap; refusing to serve it",
                bytes.len(),
                MAX_MANIFEST_FRAME
            ),
        )
        .await;
    }
    send.write_u8(0).await?;
    send.write_u64_le(bytes.len() as u64).await?;
    send.write_all(&bytes).await?;
    send.shutdown().await?;
    Ok(())
}

/// Serve a `file` op against a FOLDER offer: load + verify the manifest, find the entry, resolve
/// the entry's path strictly beneath `dir_path` (M8 canonicalize/symlink guard), run the per-entry
/// source check against the entry's own `FileRef`, then stream the bytes.
async fn serve_folder_file_op(
    send: &mut (impl AsyncWrite + Unpin),
    dir_path: &Path,
    folder_ref: &FolderRef,
    manifest_path: &Path,
    rel_path: &str,
    offset: u64,
) -> Result<(), NetError> {
    // Load + re-verify the manifest BEFORE trusting a single entry in it (chorus H4). The sender's
    // own store could have been tampered; `decode_and_verify` re-checks the cap, parses, and
    // hashes the bytes against the ticket's commitment.
    let manifest_bytes = read_stored_manifest(manifest_path).await?;
    let manifest = match decode_and_verify_manifest(&manifest_bytes, &folder_ref.root_hash) {
        Ok(o) => o.into_manifest(),
        Err(e) => return send_error(send, &format!("the sender's manifest failed verification: {e}")).await,
    };
    let entry = match manifest_entry_for(&manifest.entries, rel_path) {
        Ok(e) => e,
        Err(why) => return send_error(send, &why).await,
    };
    // Resolve the entry's path strictly beneath the shared dir (M8 canonicalize/symlink guard).
    let file_path = match resolve_within_root(dir_path, rel_path) {
        Ok(p) => p,
        Err(why) => return send_error(send, &why).await,
    };
    // Build the entry's FileRef and run the per-file source check against the entry's own size.
    let entry_ref = FileRef {
        name: entry.rel_path.clone(),
        size: entry.size,
        sha256: entry.sha256,
        md5: entry.md5,
        mime: None,
    };
    match mascara_core::check_source(&file_path, &entry_ref) {
        SourceCheck::Missing => {
            return send_error(
                send,
                "the source file is no longer present on the sender's device",
            )
            .await
        }
        SourceCheck::Changed { expected, actual } => {
            return send_error(
                send,
                &format!(
                    "the source file changed since the ticket was issued (was {expected} bytes, now {actual})"
                ),
            )
            .await
        }
        SourceCheck::Ok => {}
    }
    stream_file(send, &file_path, entry.size, offset).await
}

/// Stream `file` from `offset`, framing `[u8 status=0][u64-LE remaining = size − offset][bytes]`.
/// The caller is responsible for the source check and the `offset ≤ size` guarantee.
async fn stream_file(
    send: &mut (impl AsyncWrite + Unpin),
    path: &Path,
    size: u64,
    offset: u64,
) -> Result<(), NetError> {
    if offset > size {
        return send_error(send, &format!("offset {offset} exceeds file size {size}")).await;
    }
    let remaining = size - offset;
    let mut file = tokio::fs::File::open(path).await?;
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset)).await?;
    }
    send.write_u8(0).await?;
    send.write_u64_le(remaining).await?;
    tokio::io::copy(&mut file, send).await?;
    send.shutdown().await?;
    Ok(())
}

/// Hold a connection open (bounded) until the peer closes it, before dropping it. Dropping
/// immediately after writing a small response can send the CONNECTION_CLOSE ahead of the
/// response on a fast link, which the peer sees as a truncated read (mined verbatim from the
/// quarry's `conn::drain_connection` — the same race, the same fix).
pub async fn drain(conn: &iroh::endpoint::Connection) {
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
}

/// The `serve` accept loop (DESIGN §4, spec D-serve). Runs until the endpoint is closed.
///
/// Registry auto-compact runs once at startup (MR-8's revoke/expire-drop mechanism landed at M1;
/// this is the M2 runtime wiring that actually triggers it). Per connection: pre-filter
/// `conn.remote_id()` against the set of ACTIVE issued-ticket recipients (cheap set lookup)
/// before accepting any stream, with [`UnknownRemoteLimiter`] as a DoS floor for remotes outside
/// that set. Per stream: a fresh registry snapshot (so a revocation mid-serve takes effect
/// immediately) is handed to [`handle_request`].
pub async fn run(ep: iroh::Endpoint, home: PathBuf) -> Result<(), NetError> {
    let registry = mascara_core::Registry::new(mascara_core::FileStore::at(&home));
    registry.compact(Utc::now())?;

    let limiter = std::sync::Arc::new(UnknownRemoteLimiter::with_defaults());

    while let Some(incoming) = ep.accept().await {
        let home = home.clone();
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };
            let remote_id = *conn.remote_id().as_bytes();

            let known: HashSet<[u8; 32]> = match mascara_core::FileStore::at(&home).load() {
                Ok(t) => t
                    .tickets
                    .iter()
                    .filter_map(|r| r.recipient_transport_pk)
                    .collect(),
                Err(_) => return,
            };
            if !known.contains(&remote_id) && !limiter.allow(remote_id) {
                conn.close(1u32.into(), b"rate limited");
                return;
            }

            // One bi-stream per op, SEQUENTIALLY, until the peer closes the connection (D8: one
            // active op per connection). A folder pull is one connection carrying N `file` ops —
            // M2's single accept_bi would strand every op after the first (M3 stage-3 fix). The
            // registry snapshot is re-loaded per stream so a revocation mid-serve still takes
            // effect on the very next op.
            loop {
                let (send, recv) = match conn.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => break, // peer closed (or the connection died) — done serving it
                };
                let fresh_tickets = match mascara_core::FileStore::at(&home).load() {
                    Ok(t) => t,
                    Err(_) => break,
                };
                let offers = OfferStore::at(&home);
                let lookup = move |n: &Nonce| offers.find(n).ok().flatten();
                let _ = handle_request(send, recv, remote_id, &fresh_tickets, lookup, Utc::now()).await;
            }
            drain(&conn).await;
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use mascara_core::{IssuedRecord, Nonce};

    fn registry_with(record: IssuedRecord) -> IssuedTickets {
        let mut t = IssuedTickets::default();
        t.issue(record).unwrap();
        t
    }

    #[test]
    fn happy_path_authorized() {
        let now = Utc::now();
        let remote = [7u8; 32];
        let r = IssuedRecord::new(Nonce::mint(), Some("f".into()), now, None, remote);
        let nonce = r.nonce;
        let tickets = registry_with(r);
        assert!(authorize(&tickets, &nonce, remote, now).is_ok());
    }

    #[test]
    fn unknown_nonce_refused() {
        let now = Utc::now();
        let tickets = IssuedTickets::default();
        assert_eq!(authorize(&tickets, &Nonce::mint(), [1u8; 32], now), Err(Refusal::InvalidTicket));
    }

    #[test]
    fn revoked_nonce_refused() {
        let now = Utc::now();
        let remote = [7u8; 32];
        let r = IssuedRecord::new(Nonce::mint(), Some("f".into()), now, None, remote);
        let nonce = r.nonce;
        let mut tickets = registry_with(r);
        tickets.revoke(&nonce).unwrap();
        assert_eq!(authorize(&tickets, &nonce, remote, now), Err(Refusal::InvalidTicket));
    }

    #[test]
    fn expired_ticket_refused() {
        let now = Utc::now();
        let remote = [7u8; 32];
        let r = IssuedRecord::new(Nonce::mint(), Some("f".into()), now, Some(now - ChronoDuration::hours(1)), remote);
        let nonce = r.nonce;
        let tickets = registry_with(r);
        assert_eq!(authorize(&tickets, &nonce, remote, now), Err(Refusal::InvalidTicket));
    }

    /// `sem_auth_not_nonce_secrecy`: a valid, active nonce presented by a remote OTHER than the
    /// one it was sealed to is refused — the nonce alone is not proof of authorization.
    #[test]
    fn wrong_remote_refused() {
        let now = Utc::now();
        let sealed_to = [7u8; 32];
        let stranger = [9u8; 32];
        let r = IssuedRecord::new(Nonce::mint(), Some("f".into()), now, None, sealed_to);
        let nonce = r.nonce;
        let tickets = registry_with(r);
        assert_eq!(authorize(&tickets, &nonce, stranger, now), Err(Refusal::WrongRemote));
    }

    #[test]
    fn unknown_remote_limiter_caps_then_resets() {
        let limiter = UnknownRemoteLimiter::new(Duration::from_millis(50), 2);
        let remote = [1u8; 32];
        assert!(limiter.allow(remote));
        assert!(limiter.allow(remote));
        assert!(!limiter.allow(remote), "third attempt within the window must be capped");
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.allow(remote), "a new window resets the count");
    }

    #[test]
    fn offer_store_round_trips_and_absent_is_none() {
        let home = tempfile::tempdir().unwrap();
        let store = OfferStore::at(home.path());
        let nonce = Nonce::mint();
        assert!(store.find(&nonce).unwrap().is_none());
        let record = OfferRecord {
            nonce,
            payload: OfferPayload::File {
                path: PathBuf::from("/tmp/does-not-matter.bin"),
                file_ref: FileRef {
                    name: "a.bin".into(),
                    size: 4,
                    sha256: [1u8; 32],
                    md5: [2u8; 16],
                    mime: None,
                },
            },
            grant: Grant::Download,
        };
        store.record(record.clone()).unwrap();
        assert_eq!(store.find(&nonce).unwrap(), Some(record));
    }

    // --- Full protocol round trips over tokio::io::duplex (mining note: the quarry's duplex
    // technique) live in `tests/xfer.rs` — they need both `handle_request` (here) and
    // `engine::pull_file` (the client) together, so they're written once as integration tests
    // rather than duplicated per module.

    /// Real (loopback) iroh regression test, mined from the quarry's
    /// `xfer_error_response_survives_connection_close`: a small error response must survive an
    /// eager connection close on the client side — the CONNECTION_CLOSE frame must not outrace it.
    #[tokio::test]
    async fn error_response_survives_connection_close() {
        use crate::endpoint::build_loopback_endpoint;

        let server_identity = mascara_core::Identity::mint();
        let server_ep = build_loopback_endpoint(&server_identity).await.unwrap();
        let server_ep2 = server_ep.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server_ep2.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let remote_id = *conn.remote_id().as_bytes();
                    let Ok((send, recv)) = conn.accept_bi().await else { return };
                    let tickets = IssuedTickets::default(); // empty ⇒ every nonce is unknown
                    let _ =
                        handle_request(send, recv, remote_id, &tickets, |_| None, Utc::now()).await;
                    drain(&conn).await;
                });
            }
        });

        let client_identity = mascara_core::Identity::mint();
        let client_ep = build_loopback_endpoint(&client_identity).await.unwrap();
        let server_addr = server_ep.addr();

        for round in 0..3 {
            let conn = client_ep.connect(server_addr.clone(), crate::endpoint::XFER_ALPN).await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            let req = Request { v: 1, nonce: Nonce::mint(), op: Op::Manifest };
            let bytes = serde_json::to_vec(&req).unwrap();
            send.write_u32_le(bytes.len() as u32).await.unwrap();
            send.write_all(&bytes).await.unwrap();
            send.shutdown().await.unwrap();

            let status = recv.read_u8().await.unwrap();
            assert_eq!(status, 1, "round {round}: expected a refusal status");
            let elen = recv.read_u32_le().await.unwrap();
            let mut ebuf = vec![0u8; elen as usize];
            recv.read_exact(&mut ebuf).await.unwrap();
            let msg = String::from_utf8(ebuf).unwrap();
            assert!(msg.contains("unknown, revoked, or expired"), "round {round}: got {msg}");
            conn.close(0u32.into(), b"");
        }

        client_ep.close().await;
        server_ep.close().await;
    }
}
