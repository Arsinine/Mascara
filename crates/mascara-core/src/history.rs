//! The transfer history: `~/.mascara/transfers/history.json` (spec Data Model / D9, DESIGN.md §7).
//!
//! Records **what you hold** — name, hash, size, when — for the white/greyed folder view and for
//! re-download/resume. **Local-only, purgeable, never synced** (MAS-INV-2/6, `sem_history_local_only`):
//! nothing in this module shares, sends, or replicates the store; there is no network I/O at all.
//!
//! **Origin stripped on completion (MR-7 / spec D9 amended v0.6).** The sender's endpoint
//! (`origin`) is retained **only while a transfer is resumable** — `InProgress` or `Partial` — and
//! is dropped from the record the moment the transfer completes. What remains is a what-you-hold
//! record (name/hash/size/when), not a who-from trace (`sem_history_origin_stripped_on_completion`).
//!
//! **Auto-purge is OFF by default (MR-15).** A default-constructed [`HistoryConfig`] never
//! auto-purges; an explicit retention window may be set, but it is opt-in
//! (`sem_autopurge_default_off`).
//!
//! **The shape mirrors [`crate::registry`].** A pure state machine ([`History`]) over a storage
//! trait ([`HistoryStore`]) with an atomic file backend ([`FileStore`]); the same tmp+rename
//! discipline as `issued.json` so a concurrent record-complete and record-partial can never tear
//! the file.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

pub const HISTORY_FILE: &str = "history.json";
/// Schema discriminant for `history.json` (mirrors `REGISTRY_VERSION`).
pub const HISTORY_VERSION: u8 = 1;

/// The record's lifecycle state. Origin (the sender's endpoint) rides only the resumable states.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum TransferState {
    /// A transfer has started but is not yet known to be complete. The sender's endpoint is kept
    /// so the receiver can resume / re-dial while the transfer is still live.
    InProgress {
        /// The sender's reachable endpoint (LAN addr + coordinator relay URL). Stripped on
        /// completion (MR-7) — never kept once the transfer is done.
        origin: String,
        started_at: DateTime<Utc>,
    },
    /// A partial download — interrupted, with bytes-on-disk recorded for resume. The sender's
    /// endpoint is kept so the receiver can re-dial to resume.
    Partial {
        /// Stripped on completion (MR-7).
        origin: String,
        started_at: DateTime<Utc>,
        /// Bytes received so far (0 ≤ bytes < size). Used by the resume offset logic in
        /// `mascara-net::engine` (M3 stage 2); recorded here so a re-open after a crash knows where
        /// to resume.
        bytes_so_far: u64,
    },
    /// The transfer finished and the file is fully received and hash-verified. **No `origin`** —
    /// the sender's endpoint is dropped the moment the transfer completes (MR-7).
    Completed { completed_at: DateTime<Utc> },
}

impl TransferState {
    /// True if this state is resumable (i.e. the transfer is not yet complete and the origin is
    /// therefore still held). `InProgress` and `Partial` are resumable; `Completed` is not.
    pub fn is_resumable(&self) -> bool {
        matches!(self, TransferState::InProgress { .. } | TransferState::Partial { .. })
    }

    /// The sender's endpoint, if this state still holds it (MR-7: only while resumable).
    pub fn origin(&self) -> Option<&str> {
        match self {
            TransferState::InProgress { origin, .. } | TransferState::Partial { origin, .. } => {
                Some(origin)
            }
            TransferState::Completed { .. } => None,
        }
    }
}

/// One history record — the what-you-hold facts (name/hash/size/when) plus the lifecycle state that
/// decides whether the sender's origin is still retained. Hash/size field types mirror
/// [`crate::ticket::FileRef`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HistoryRecord {
    /// A stable id for this record (so the CLI's re-download / resume can name it). A 128-bit
    /// random value, hex-encoded in JSON (mirrors [`crate::ticket::Nonce`]'s hex serde).
    pub id: TransferId,
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
    /// Advisory legacy-catalog interop hash (MR-11), carried from the ticket.
    pub md5: [u8; 16],
    pub state: TransferState,
}

/// A transfer-history record id: 128 bits of OS CSPRNG, hex-encoded in JSON (mirrors `Nonce`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TransferId([u8; 16]);

impl TransferId {
    pub fn mint() -> Self {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        TransferId(b)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for TransferId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for TransferId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransferId({})", self.to_hex())
    }
}

impl From<TransferId> for String {
    fn from(id: TransferId) -> String {
        id.to_hex()
    }
}

impl TryFrom<String> for TransferId {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s.trim()).map_err(|e| format!("bad transfer id hex: {e}"))?;
        let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
            format!("transfer id must be 16 bytes, got {}", bytes.len())
        })?;
        Ok(TransferId(arr))
    }
}

/// The history store state: a pure, I/O-free state machine over the records + an optional
/// auto-purge config (MR-15).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct History {
    pub v: u8,
    pub records: Vec<HistoryRecord>,
}

impl Default for History {
    fn default() -> Self {
        History { v: HISTORY_VERSION, records: Vec::new() }
    }
}

/// The auto-purge policy (MR-15). OFF by default — a default-constructed [`HistoryConfig`] never
/// drops records automatically (`sem_autopurge_default_off`); a caller may opt in to a retention
/// window, after which `purge_older_than` drops completed records past it. In-progress/partial
/// records are always retained (they are resumable — origin is still held, MR-7).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct HistoryConfig {
    /// Auto-purge retention window for **completed** records. `None` (the default) ⇒ never
    /// auto-purge. Some(ts) ⇒ completed records older than `ts` are dropped by `purge_older_than`.
    pub retention: Option<chrono::Duration>,
}

impl HistoryConfig {
    /// The default config — auto-purge OFF (MR-15).
    pub fn new() -> Self {
        Self::default()
    }

    /// Opt into a retention window. Completed records older than the window are auto-purged.
    pub fn with_retention(mut self, retention: chrono::Duration) -> Self {
        self.retention = Some(retention);
        self
    }
}

impl History {
    /// Record a freshly-started transfer with its sender endpoint (the resumable state — origin
    /// retained). A duplicate id is a reasoned refusal (ids are 128-bit CSPRNG; a collision is a
    /// bug, not a coincidence — mirrors the registry's issue-rejection).
    #[allow(clippy::too_many_arguments)]
    pub fn record_in_progress(
        &mut self,
        id: TransferId,
        name: String,
        size: u64,
        sha256: [u8; 32],
        md5: [u8; 16],
        origin: String,
        started_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        if self.records.iter().any(|r| r.id == id) {
            return Err(CoreError::History(format!("transfer {id} is already recorded")));
        }
        self.records.push(HistoryRecord {
            id,
            name,
            size,
            sha256,
            md5,
            state: TransferState::InProgress { origin, started_at },
        });
        Ok(())
    }

    /// Update bytes-so-far for a partial download (resume). Keeps the origin (still resumable).
    /// Unknown id ⇒ reasoned refusal; calling on a Completed record ⇒ reasoned refusal (no resume
    /// after completion).
    pub fn record_partial(
        &mut self,
        id: TransferId,
        bytes_so_far: u64,
        at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        let r = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| CoreError::History(format!("no transfer record with id {id}")))?;
        match &r.state {
            TransferState::InProgress { origin, started_at } => {
                r.state = TransferState::Partial {
                    origin: origin.clone(),
                    started_at: *started_at,
                    bytes_so_far,
                };
            }
            TransferState::Partial { origin, started_at, .. } => {
                r.state = TransferState::Partial {
                    origin: origin.clone(),
                    started_at: *started_at,
                    bytes_so_far,
                };
            }
            TransferState::Completed { .. } => {
                return Err(CoreError::History(format!(
                    "transfer {id} is already completed — cannot record a partial"
                )));
            }
        }
        let _ = at; // `at` is kept on the signature for symmetry with record_completed; not stored
                    // (started_at is the resumable-since timestamp; the partial is an update of it).
        Ok(())
    }

    /// Mark a transfer completed — **stripping the sender's origin** (MR-7). The state becomes
    /// `Completed { completed_at }`, with no `origin` field. Unknown id ⇒ reasoned refusal.
    pub fn record_completed(
        &mut self,
        id: TransferId,
        completed_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        let r = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| CoreError::History(format!("no transfer record with id {id}")))?;
        r.state = TransferState::Completed { completed_at };
        Ok(())
    }

    /// Purge the entire history (spec D9 — "purgeable"). After this the store is empty. Also the
    /// handler for the CLI's `mascara history --purge`.
    pub fn purge_all(&mut self) {
        self.records.clear();
    }

    /// Time-based auto-purge (MR-15). Drops **completed** records older than the cutoff; leaves
    /// InProgress/Partial records alone (they are resumable — origin is still held, MR-7). With
    /// `retention = None` (the default) this is a no-op (`sem_autopurge_default_off`).
    pub fn purge_older_than(&mut self, now: DateTime<Utc>, config: HistoryConfig) {
        let Some(window) = config.retention else {
            return; // auto-purge OFF by default
        };
        let cutoff = now - window;
        self.records.retain(|r| match &r.state {
            TransferState::Completed { completed_at } => *completed_at >= cutoff,
            // Resumable records are never auto-purged — the origin is still needed for resume.
            TransferState::InProgress { .. } | TransferState::Partial { .. } => true,
        });
    }

    /// Iterate the records (for the white/greyed view: Completed = white = "you hold this",
    /// InProgress/Partial = greyed = "in flight").
    pub fn records(&self) -> &[HistoryRecord] {
        &self.records
    }
}

/// The storage seam — the same shape as [`crate::registry::IssuedStore`]: a backend loads and stores
/// the whole state; the state machine above is oblivious to where it lives.
pub trait HistoryStore {
    fn load(&self) -> Result<History, CoreError>;
    fn store(&self, history: &History) -> Result<(), CoreError>;
}

/// The file backend: `<home>/transfers/history.json`, written atomically (mirrors
/// `registry::FileStore`).
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn at(home: &Path) -> Self {
        FileStore { path: home.join("transfers").join(HISTORY_FILE) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl HistoryStore for FileStore {
    fn load(&self) -> Result<History, CoreError> {
        if !self.path.is_file() {
            return Ok(History::default()); // absent history = nothing received yet
        }
        let raw = fs::read_to_string(&self.path)?;
        let parsed: History = serde_json::from_str(&raw)?;
        if parsed.v != HISTORY_VERSION {
            return Err(CoreError::History(format!(
                "unsupported {HISTORY_FILE} version {} (this Mascara understands v{HISTORY_VERSION})",
                parsed.v
            )));
        }
        Ok(parsed)
    }

    fn store(&self, history: &History) -> Result<(), CoreError> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(history)?;
        atomic_write(&self.path, json.as_bytes())
    }
}

/// A convenience wrapper that composes a store with the state machine (load → mutate → store), the
/// shape the CLI uses. Each call is a full atomic round-trip — mirrors [`crate::registry::Registry`].
pub struct HistoryLog<S: HistoryStore> {
    store: S,
    config: HistoryConfig,
}

impl<S: HistoryStore> HistoryLog<S> {
    pub fn new(store: S) -> Self {
        HistoryLog { store, config: HistoryConfig::default() }
    }

    pub fn with_config(store: S, config: HistoryConfig) -> Self {
        HistoryLog { store, config }
    }

    pub fn config(&self) -> HistoryConfig {
        self.config
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_in_progress(
        &self,
        id: TransferId,
        name: String,
        size: u64,
        sha256: [u8; 32],
        md5: [u8; 16],
        origin: String,
        started_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        let mut h = self.store.load()?;
        h.record_in_progress(id, name, size, sha256, md5, origin, started_at)?;
        self.store.store(&h)
    }

    pub fn record_partial(
        &self,
        id: TransferId,
        bytes_so_far: u64,
        at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        let mut h = self.store.load()?;
        h.record_partial(id, bytes_so_far, at)?;
        self.store.store(&h)
    }

    pub fn record_completed(&self, id: TransferId, at: DateTime<Utc>) -> Result<(), CoreError> {
        let mut h = self.store.load()?;
        h.record_completed(id, at)?;
        self.run_auto_purge(&mut h, at);
        self.store.store(&h)
    }

    pub fn purge_all(&self) -> Result<(), CoreError> {
        let mut h = self.store.load()?;
        h.purge_all();
        self.store.store(&h)
    }

    pub fn list(&self) -> Result<Vec<HistoryRecord>, CoreError> {
        Ok(self.store.load()?.records)
    }

    /// Auto-purge runs after a state-changing op if a retention window is configured. With the
    /// default config (retention = None) this is a no-op.
    fn run_auto_purge(&self, h: &mut History, now: DateTime<Utc>) {
        h.purge_older_than(now, self.config);
    }
}

/// Atomic write — identical discipline to `registry::atomic_write` (unique temp + rename), so a
/// concurrent record-complete and record-partial can never tear `history.json`.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(".{HISTORY_FILE}.{}.tmp", hex::encode(suffix)));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // --- the pure state machine ---

    #[test]
    fn record_in_progress_keeps_origin() {
        let now = Utc::now();
        let mut h = History::default();
        let id = TransferId::mint();
        h.record_in_progress(
            id,
            "a.bin".into(),
            16,
            [1u8; 32],
            [2u8; 16],
            "192.0.2.1:41000".into(),
            now,
        )
        .unwrap();
        assert_eq!(h.records().len(), 1);
        assert_eq!(h.records()[0].state.origin(), Some("192.0.2.1:41000"));
        assert!(h.records()[0].state.is_resumable());
    }

    #[test]
    fn record_partial_keeps_origin_for_resume() {
        let now = Utc::now();
        let mut h = History::default();
        let id = TransferId::mint();
        h.record_in_progress(
            id,
            "a.bin".into(),
            100,
            [1u8; 32],
            [2u8; 16],
            "192.0.2.1:41000".into(),
            now,
        )
        .unwrap();
        h.record_partial(id, 50, now).unwrap();
        match &h.records()[0].state {
            TransferState::Partial { origin, bytes_so_far, .. } => {
                assert_eq!(origin, "192.0.2.1:41000", "origin retained while partial (resume needs it)");
                assert_eq!(*bytes_so_far, 50);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(h.records()[0].state.is_resumable());
    }

    /// SEMANTIC_MODEL `sem_history_origin_stripped_on_completion` (MR-7) — origin is present while
    /// resumable (InProgress/Partial) and absent the moment completion is recorded.
    #[test]
    fn sem_history_origin_stripped_on_completion() {
        let now = Utc::now();
        let mut h = History::default();
        let id = TransferId::mint();

        // InProgress: origin held.
        h.record_in_progress(
            id,
            "a.bin".into(),
            100,
            [1u8; 32],
            [2u8; 16],
            "192.0.2.1:41000".into(),
            now,
        )
        .unwrap();
        assert_eq!(
            h.records()[0].state.origin(),
            Some("192.0.2.1:41000"),
            "origin retained while InProgress (resume needs it)"
        );

        // Partial mid-way: still held.
        h.record_partial(id, 50, now).unwrap();
        assert_eq!(h.records()[0].state.origin(), Some("192.0.2.1:41000"));

        // Complete: origin is dropped. The serialized record must not contain the endpoint string.
        h.record_completed(id, now).unwrap();
        assert_eq!(h.records()[0].state.origin(), None, "MR-7: origin dropped on completion");
        assert!(!h.records()[0].state.is_resumable());
        let json = serde_json::to_string(h.records()).unwrap();
        assert!(
            !json.contains("192.0.2.1"),
            "MR-7: completed record must not serialise the sender's endpoint: {json}"
        );
    }

    #[test]
    fn duplicate_id_rejected() {
        let now = Utc::now();
        let id = TransferId::mint();
        let mut h = History::default();
        h.record_in_progress(id, "a".into(), 1, [0u8; 32], [0u8; 16], "o".into(), now).unwrap();
        let err = h
            .record_in_progress(id, "b".into(), 1, [0u8; 32], [0u8; 16], "o".into(), now)
            .unwrap_err();
        assert!(matches!(err, CoreError::History(_)), "got: {err}");
    }

    #[test]
    fn unknown_id_operations_are_reasoned() {
        let mut h = History::default();
        let id = TransferId::mint();
        let err = h.record_partial(id, 1, Utc::now()).unwrap_err();
        assert!(matches!(err, CoreError::History(_)), "got: {err}");
        let err = h.record_completed(id, Utc::now()).unwrap_err();
        assert!(matches!(err, CoreError::History(_)), "got: {err}");
    }

    #[test]
    fn completed_cannot_record_partial() {
        let now = Utc::now();
        let id = TransferId::mint();
        let mut h = History::default();
        h.record_in_progress(id, "a".into(), 100, [0u8; 32], [0u8; 16], "o".into(), now).unwrap();
        h.record_completed(id, now).unwrap();
        let err = h.record_partial(id, 50, now).unwrap_err();
        assert!(matches!(err, CoreError::History(_)), "got: {err}");
    }

    /// SEMANTIC_MODEL `sem_history_local_only` (MAS-INV-2/6, D9) — purge empties the store, and the
    /// module performs no sharing/sync/replication of any kind. Structural sweep: no network symbol
    /// appears in this source (comment-stripped, so the prose that *names* the guarantee doesn't
    /// self-trip), and behavioural: purge_all leaves zero records.
    #[test]
    fn sem_history_local_only() {
        // Behavioural: purge_all empties the store.
        let now = Utc::now();
        let mut h = History::default();
        h.record_in_progress(
            TransferId::mint(),
            "a".into(),
            1,
            [0u8; 32],
            [0u8; 16],
            "o".into(),
            now,
        )
        .unwrap();
        h.record_in_progress(
            TransferId::mint(),
            "b".into(),
            1,
            [0u8; 32],
            [0u8; 16],
            "o".into(),
            now,
        )
        .unwrap();
        assert_eq!(h.records().len(), 2);
        h.purge_all();
        assert_eq!(h.records().len(), 0, "purge empties the store");

        // Structural: this module's non-test code names no network-y symbol — it neither shares
        // nor syncs the store. Scan only the production body (before `#[cfg(test)]`) so this guard's
        // own FORBIDDEN list doesn't self-trip on the strings it names.
        let src = include_str!("history.rs");
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
                "sem_history_local_only: history.rs names a network symbol `{sym}` — the history \
                 store is local-only, never shared or synced"
            );
        }
    }

    /// SEMANTIC_MODEL `sem_autopurge_default_off` (MR-15) — a default-constructed config does not
    /// auto-purge; only an explicit `with_retention` opts in.
    #[test]
    fn sem_autopurge_default_off() {
        // Default config ⇒ retention None ⇒ no auto-purge.
        let cfg = HistoryConfig::default();
        assert_eq!(cfg.retention, None, "auto-purge must be OFF by default (MR-15)");

        // Behavioural: a long time passes, and with the default config nothing is dropped — even
        // completed records.
        let now = Utc::now();
        let long_ago = now - Duration::days(365 * 10);
        let mut h = History::default();
        let id = TransferId::mint();
        h.record_in_progress(id, "a".into(), 1, [0u8; 32], [0u8; 16], "o".into(), long_ago).unwrap();
        h.record_completed(id, long_ago).unwrap();
        let before = h.records().len();
        h.purge_older_than(now, HistoryConfig::default());
        assert_eq!(
            h.records().len(),
            before,
            "default config must not auto-purge even very old completed records (MR-15)"
        );

        // Opting in with a retention window DOES drop the old completed record.
        let cfg = HistoryConfig::default().with_retention(Duration::days(30));
        h.purge_older_than(now, cfg);
        assert_eq!(h.records().len(), 0, "opt-in retention drops old completed records");

        // But a resumable record is never auto-purged, even with retention set.
        let mut h = History::default();
        let id = TransferId::mint();
        h.record_in_progress(id, "a".into(), 1, [0u8; 32], [0u8; 16], "o".into(), long_ago).unwrap();
        h.purge_older_than(now, cfg);
        assert_eq!(
            h.records().len(),
            1,
            "resumable (InProgress/Partial) records are never auto-purged — origin is still held"
        );
    }

    // --- the file backend + composed HistoryLog ---

    #[test]
    fn file_store_round_trip_and_absent_is_empty() {
        let home = tempfile::tempdir().unwrap();
        let store = FileStore::at(home.path());
        assert!(store.load().unwrap().records.is_empty(), "absent history loads as empty");

        let log = HistoryLog::new(FileStore::at(home.path()));
        let now = Utc::now();
        let id = TransferId::mint();
        log.record_in_progress(
            id,
            "a.bin".into(),
            16,
            [1u8; 32],
            [2u8; 16],
            "192.0.2.10:41000".into(),
            now,
        )
        .unwrap();
        assert_eq!(log.list().unwrap().len(), 1);
        assert_eq!(log.list().unwrap()[0].state.origin(), Some("192.0.2.10:41000"));

        log.record_completed(id, now).unwrap();
        assert_eq!(log.list().unwrap()[0].state.origin(), None, "MR-7 on the round-trip");

        assert!(store.path().is_file(), "the file exists and re-parses");
        assert_eq!(store.load().unwrap().records[0].id, id);
    }

    #[test]
    fn purge_via_log_empties_the_file() {
        let home = tempfile::tempdir().unwrap();
        let log = HistoryLog::new(FileStore::at(home.path()));
        let now = Utc::now();
        log.record_in_progress(
            TransferId::mint(),
            "a".into(),
            1,
            [0u8; 32],
            [0u8; 16],
            "o".into(),
            now,
        )
        .unwrap();
        assert_eq!(log.list().unwrap().len(), 1);
        log.purge_all().unwrap();
        assert_eq!(log.list().unwrap().len(), 0);
        // The file still exists (we wrote an empty array), and re-parses as empty.
        assert_eq!(FileStore::at(home.path()).load().unwrap().records.len(), 0);
    }

    /// A concurrent record-partial and record-complete must never tear `history.json`: a reader
    /// loading in a tight loop while writers hammer the file must never see a parse error. Same
    /// discipline as `registry::concurrent_writes_never_tear_the_file`.
    #[test]
    fn concurrent_writes_never_tear_the_file() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().to_path_buf();

        // Seed one in-progress record so writers have a stable id to act on.
        let seed = HistoryLog::new(FileStore::at(&home_path));
        let now = Utc::now();
        let id = TransferId::mint();
        seed.record_in_progress(
            id,
            "a".into(),
            100,
            [0u8; 32],
            [0u8; 16],
            "o".into(),
            now,
        )
        .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        // Writers: record partials and completions on the seeded id, plus fresh records.
        for _ in 0..4 {
            let p = home_path.clone();
            handles.push(std::thread::spawn(move || {
                let log = HistoryLog::new(FileStore::at(&p));
                for i in 0..25 {
                    let _ = log.record_partial(id, i % 100, Utc::now());
                    let _ = log.record_completed(id, Utc::now());
                    let _ = log.record_in_progress(
                        TransferId::mint(),
                        format!("b{i}"),
                        1,
                        [0u8; 32],
                        [0u8; 16],
                        "o".into(),
                        Utc::now(),
                    );
                }
            }));
        }

        // Reader: load in a tight loop; a torn file would surface as a parse error here.
        let p = home_path.clone();
        let stop_reader = stop.clone();
        let reader = std::thread::spawn(move || {
            let store = FileStore::at(&p);
            while !stop_reader.load(Ordering::Relaxed) {
                store.load().expect("history.json must always parse — never torn");
            }
        });

        for h in handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        FileStore::at(&home_path).load().expect("final history.json parses");
    }
}
