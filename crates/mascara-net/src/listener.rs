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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use mascara_core::{FileRef, Grant, IssuedStore, IssuedTickets, Nonce, SourceCheck};

use crate::error::NetError;

/// Request frame length cap (DESIGN §4) — checked BEFORE allocating the buffer.
pub const MAX_REQUEST_FRAME: usize = 8 * 1024;

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

/// One nonce this device can currently serve: the real local file path (never sealed, never
/// sent — `sem_ticket_endpoint_only_sealed`'s sibling guarantee for the path), the ticket's
/// `file_ref` (for the MR-14 source check + size), and its `grant` (so a `sync` ticket can be
/// recognised and refused even though the registry itself doesn't carry grant).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OfferRecord {
    pub nonce: Nonce,
    pub path: PathBuf,
    pub file_ref: FileRef,
    pub grant: Grant,
}

const OFFERS_FILE: &str = "offers.json";
const OFFERS_VERSION: u8 = 1;

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
/// (mirrors `mascara-core::registry`'s discipline).
pub struct OfferStore {
    path: PathBuf,
}

impl OfferStore {
    pub fn at(home: &Path) -> Self {
        OfferStore { path: home.join("tickets").join(OFFERS_FILE) }
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
    /// issue time.
    pub fn record(&self, record: OfferRecord) -> Result<(), NetError> {
        let mut f = self.load()?;
        f.entries.retain(|r| r.nonce != record.nonce);
        f.entries.push(record);
        self.store(&f)
    }

    /// Look up the local serve facts for `nonce`, if this device has any recorded.
    pub fn find(&self, nonce: &Nonce) -> Result<Option<OfferRecord>, NetError> {
        Ok(self.load()?.entries.into_iter().find(|r| &r.nonce == nonce))
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), NetError> {
    use rand::RngCore;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(".{OFFERS_FILE}.{}.tmp", hex::encode(suffix)));
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

/// Handle one request/response over an already-open bi-stream (DESIGN §4). Generic over
/// `AsyncRead+AsyncWrite`, so the same logic runs over `tokio::io::duplex` in tests and a real
/// iroh stream in production.
///
/// `remote_id` is the QUIC-authenticated peer identity (`conn.remote_id()`) — the only
/// trustworthy claim of who is asking. `tickets` should be a **freshly loaded** registry snapshot
/// (re-read from disk per request by the caller, so a revocation during `serve` takes effect
/// immediately). `lookup_offer` resolves a nonce to this device's local serve facts.
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

    let (path, offset) = match req.op {
        Op::Manifest => {
            return send_error(&mut send, "folder manifests are not supported yet (M3)").await
        }
        Op::File { path, offset } => (path, offset),
    };
    if path != offer.file_ref.name {
        return send_error(&mut send, "the requested path does not match this ticket's file").await;
    }

    match mascara_core::check_source(&offer.path, &offer.file_ref) {
        SourceCheck::Missing => {
            return send_error(&mut send, "the source file is no longer present on the sender's device")
                .await
        }
        SourceCheck::Changed { expected, actual } => {
            return send_error(
                &mut send,
                &format!("the source file changed since the ticket was issued (was {expected} bytes, now {actual})"),
            )
            .await
        }
        SourceCheck::Ok => {}
    }

    let size = offer.file_ref.size;
    if offset > size {
        return send_error(&mut send, &format!("offset {offset} exceeds file size {size}")).await;
    }
    let remaining = size - offset;

    let mut file = tokio::fs::File::open(&offer.path).await?;
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset)).await?;
    }
    send.write_u8(0).await?;
    send.write_u64_le(remaining).await?;
    tokio::io::copy(&mut file, &mut send).await?;
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

            let (send, recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let fresh_tickets = match mascara_core::FileStore::at(&home).load() {
                Ok(t) => t,
                Err(_) => return,
            };
            let offers = OfferStore::at(&home);
            let lookup = move |n: &Nonce| offers.find(n).ok().flatten();
            let _ = handle_request(send, recv, remote_id, &fresh_tickets, lookup, Utc::now()).await;
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
            path: PathBuf::from("/tmp/does-not-matter.bin"),
            file_ref: FileRef { name: "a.bin".into(), size: 4, sha256: [1u8; 32], md5: [2u8; 16], mime: None },
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
