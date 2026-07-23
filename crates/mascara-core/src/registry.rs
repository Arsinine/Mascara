//! The issued-ticket registry: `~/.mascara/tickets/issued.json` (spec Data Model, DESIGN.md §7).
//!
//! Local-only, never server-stored (MAS-INV-2/6): it records the nonces *this* device has issued and
//! whether each is revoked, so M2's listener can refuse a revoked or expired ticket. It is a **pure
//! state machine** ([`IssuedTickets`]) over a **storage trait** ([`IssuedStore`]) — the validity
//! logic is unit-testable with zero I/O, and the file backing ([`FileStore`]) writes **atomically**
//! (unique temp file + rename) so a concurrent send and revoke can never tear the file (chorus).
//!
//! Validity (DESIGN §4): `is_valid(nonce, now)` = issued ∧ ¬revoked ∧ (`expires_at` absent ∨
//! `now < expires_at`). The identity/`remote_id` half of the auth predicate is M2's listener; M1
//! owns only the issued/revoked/expiry state.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::ticket::Nonce;

pub const ISSUED_FILE: &str = "issued.json";
/// Schema discriminant for `issued.json`.
pub const REGISTRY_VERSION: u8 = 1;

/// One issued ticket's registry record. The full ticket is never stored — only what the listener
/// needs to decide validity, plus a human label for `mascara tickets`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IssuedRecord {
    pub nonce: Nonce,
    /// The `file_ref.name` this ticket was issued for — display only.
    pub name: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub revoked: bool,
    pub expires_at: Option<DateTime<Utc>>,
    /// The recipient's ed25519 transport pubkey — a **disposable endpoint** the M2 listener needs
    /// for the anti-replay auth check (a valid nonce from the wrong remote is refused). `Some` only
    /// while the nonce is active; dropped to `None` on revoke/expire so the registry keeps no durable
    /// who-got-what record — never a recipient card/`npub` (MR-8).
    pub recipient_transport_pk: Option<[u8; 32]>,
}

impl IssuedRecord {
    /// A newly-issued, non-revoked record for `nonce`, stamped `issued_at = now`. The recipient's
    /// transport pubkey is stored `Some` while the ticket is active (MR-8).
    pub fn new(
        nonce: Nonce,
        name: Option<String>,
        now: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        recipient_transport_pk: [u8; 32],
    ) -> Self {
        IssuedRecord {
            nonce,
            name,
            issued_at: now,
            revoked: false,
            expires_at,
            recipient_transport_pk: Some(recipient_transport_pk),
        }
    }

    /// issued ∧ ¬revoked ∧ (no expiry ∨ now < expiry).
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        !self.revoked && self.expires_at.is_none_or(|e| now < e)
    }
}

/// The registry state: the pure, I/O-free state machine.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IssuedTickets {
    pub v: u8,
    pub tickets: Vec<IssuedRecord>,
}

impl Default for IssuedTickets {
    fn default() -> Self {
        IssuedTickets { v: REGISTRY_VERSION, tickets: Vec::new() }
    }
}

impl IssuedTickets {
    /// Record a freshly-issued nonce. A duplicate nonce is a reasoned refusal (nonces are 128-bit
    /// CSPRNG, so a collision means a bug, not a coincidence).
    pub fn issue(&mut self, record: IssuedRecord) -> Result<(), CoreError> {
        if self.tickets.iter().any(|r| r.nonce == record.nonce) {
            return Err(CoreError::Registry(format!("nonce {} is already issued", record.nonce)));
        }
        self.tickets.push(record);
        Ok(())
    }

    /// Mark a nonce revoked. Returns `true` if this call changed the state (it was live), `false` if
    /// it was already revoked. Revoking an unknown nonce is a reasoned refusal.
    pub fn revoke(&mut self, nonce: &Nonce) -> Result<bool, CoreError> {
        match self.tickets.iter_mut().find(|r| &r.nonce == nonce) {
            Some(r) => {
                let was_live = !r.revoked;
                r.revoked = true;
                // A revoked nonce is no longer active — drop the recipient endpoint (MR-8).
                r.recipient_transport_pk = None;
                Ok(was_live)
            }
            None => Err(CoreError::Registry(format!("no issued ticket with nonce {nonce}"))),
        }
    }

    /// Drop the recipient endpoint from every no-longer-valid record (revoked OR expired): once a
    /// nonce cannot authorize a transfer, its recipient `transport_pk` is dead weight and MR-8 says
    /// it must not persist as a who-got-what trace. Idempotent.
    ///
    /// Auto-triggering compaction (e.g. on M2 listener startup) is runtime wiring for M2; the
    /// mechanism and the revoke-time drop above land now.
    pub fn compact(&mut self, now: DateTime<Utc>) {
        for r in &mut self.tickets {
            if !r.is_valid(now) {
                r.recipient_transport_pk = None;
            }
        }
    }

    /// issued ∧ ¬revoked ∧ unexpired. Unknown nonce ⇒ false (never issued here).
    pub fn is_valid(&self, nonce: &Nonce, now: DateTime<Utc>) -> bool {
        self.tickets.iter().find(|r| &r.nonce == nonce).is_some_and(|r| r.is_valid(now))
    }

    /// Resolve a nonce-hex **prefix** to the single matching nonce, for `mascara tickets --revoke
    /// <id>`. Reasoned on no match or an ambiguous one.
    pub fn resolve_prefix(&self, prefix: &str) -> Result<Nonce, CoreError> {
        let prefix = prefix.trim().to_lowercase();
        if prefix.is_empty() {
            return Err(CoreError::Registry("empty ticket id".into()));
        }
        let matches: Vec<Nonce> = self
            .tickets
            .iter()
            .filter(|r| r.nonce.to_hex().starts_with(&prefix))
            .map(|r| r.nonce)
            .collect();
        match matches.as_slice() {
            [] => Err(CoreError::Registry(format!("no issued ticket matching id '{prefix}'"))),
            [one] => Ok(*one),
            many => Err(CoreError::Registry(format!(
                "id '{prefix}' is ambiguous — {} tickets match; use more characters",
                many.len()
            ))),
        }
    }
}

/// The storage seam. A backend loads and stores the whole registry state; the state machine above is
/// oblivious to where it lives.
pub trait IssuedStore {
    fn load(&self) -> Result<IssuedTickets, CoreError>;
    fn store(&self, tickets: &IssuedTickets) -> Result<(), CoreError>;
}

/// The file backend: `<home>/tickets/issued.json`, written atomically.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn at(home: &Path) -> Self {
        FileStore { path: home.join("tickets").join(ISSUED_FILE) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl IssuedStore for FileStore {
    fn load(&self) -> Result<IssuedTickets, CoreError> {
        if !self.path.is_file() {
            return Ok(IssuedTickets::default()); // absent registry = nothing issued yet
        }
        let raw = fs::read_to_string(&self.path)?;
        let parsed: IssuedTickets = serde_json::from_str(&raw)?;
        if parsed.v != REGISTRY_VERSION {
            return Err(CoreError::Registry(format!(
                "unsupported {ISSUED_FILE} version {} (this Mascara understands v{REGISTRY_VERSION})",
                parsed.v
            )));
        }
        Ok(parsed)
    }

    fn store(&self, tickets: &IssuedTickets) -> Result<(), CoreError> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(tickets)?;
        atomic_write(&self.path, json.as_bytes())
    }
}

/// A convenience wrapper that composes a store with the state machine (load → mutate → store), the
/// shape the CLI uses. Each call is a full atomic round-trip.
pub struct Registry<S: IssuedStore> {
    store: S,
}

impl<S: IssuedStore> Registry<S> {
    pub fn new(store: S) -> Self {
        Registry { store }
    }

    pub fn issue(&self, record: IssuedRecord) -> Result<(), CoreError> {
        let mut t = self.store.load()?;
        t.issue(record)?;
        self.store.store(&t)
    }

    pub fn revoke(&self, nonce: &Nonce) -> Result<bool, CoreError> {
        let mut t = self.store.load()?;
        let changed = t.revoke(nonce)?;
        self.store.store(&t)?;
        Ok(changed)
    }

    /// Revoke by nonce-hex prefix (the CLI's `--revoke <id>`), returning the resolved nonce.
    pub fn revoke_by_prefix(&self, prefix: &str) -> Result<Nonce, CoreError> {
        let mut t = self.store.load()?;
        let nonce = t.resolve_prefix(prefix)?;
        t.revoke(&nonce)?;
        self.store.store(&t)?;
        Ok(nonce)
    }

    pub fn list(&self) -> Result<Vec<IssuedRecord>, CoreError> {
        Ok(self.store.load()?.tickets)
    }

    pub fn is_valid(&self, nonce: &Nonce, now: DateTime<Utc>) -> Result<bool, CoreError> {
        Ok(self.store.load()?.is_valid(nonce, now))
    }

    /// Load → compact → store: drop the recipient endpoint from every revoked/expired record (MR-8).
    /// M2 will call this on listener startup; here it lands as an explicit, atomic round-trip.
    pub fn compact(&self, now: DateTime<Utc>) -> Result<(), CoreError> {
        let mut t = self.store.load()?;
        t.compact(now);
        self.store.store(&t)
    }
}

/// Atomic write: a **unique** temp file (so concurrent writers never share one) + rename. `rename`
/// is atomic on POSIX/Windows, so a concurrent reader sees either the old file or the new one, never
/// a torn one.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(".{ISSUED_FILE}.{}.tmp", hex::encode(suffix)));
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

    fn rec(now: DateTime<Utc>, expires_at: Option<DateTime<Utc>>) -> IssuedRecord {
        IssuedRecord::new(Nonce::mint(), Some("f.bin".into()), now, expires_at, [0x22u8; 32])
    }

    // --- the pure state machine (no I/O) ---

    #[test]
    fn issue_then_valid() {
        let now = Utc::now();
        let r = rec(now, None);
        let nonce = r.nonce;
        let mut t = IssuedTickets::default();
        t.issue(r).unwrap();
        assert!(t.is_valid(&nonce, now), "issued ∧ ¬revoked ∧ unexpired ⇒ valid");
    }

    #[test]
    fn revoke_makes_invalid_thereafter() {
        let now = Utc::now();
        let r = rec(now, None);
        let nonce = r.nonce;
        let mut t = IssuedTickets::default();
        t.issue(r).unwrap();
        assert!(t.revoke(&nonce).unwrap(), "first revoke changes state");
        assert!(!t.is_valid(&nonce, now), "revoked ⇒ invalid");
        assert!(!t.revoke(&nonce).unwrap(), "second revoke is a no-op (already revoked)");
    }

    #[test]
    fn past_expiry_is_invalid_future_is_valid() {
        let now = Utc::now();
        let r = rec(now, Some(now - Duration::hours(1))); // expired an hour ago
        let expired = r.nonce;
        let r2 = rec(now, Some(now + Duration::hours(1))); // valid for another hour
        let live = r2.nonce;
        let mut t = IssuedTickets::default();
        t.issue(r).unwrap();
        t.issue(r2).unwrap();
        assert!(!t.is_valid(&expired, now), "expires_at in the past ⇒ invalid");
        assert!(t.is_valid(&live, now), "unexpired ⇒ valid");
    }

    #[test]
    fn unknown_nonce_is_invalid_and_revoke_is_reasoned() {
        let now = Utc::now();
        let t = IssuedTickets::default();
        assert!(!t.is_valid(&Nonce::mint(), now));
        let mut t = t;
        let err = t.revoke(&Nonce::mint()).unwrap_err();
        assert!(matches!(err, CoreError::Registry(_)), "got: {err}");
    }

    #[test]
    fn duplicate_issue_rejected() {
        let now = Utc::now();
        let r = rec(now, None);
        let mut t = IssuedTickets::default();
        t.issue(r.clone()).unwrap();
        assert!(matches!(t.issue(r), Err(CoreError::Registry(_))));
    }

    #[test]
    fn prefix_resolution() {
        let now = Utc::now();
        let mut t = IssuedTickets::default();
        let r = rec(now, None);
        let nonce = r.nonce;
        t.issue(r).unwrap();
        let full = nonce.to_hex();
        assert_eq!(t.resolve_prefix(&full[..8]).unwrap(), nonce);
        assert!(matches!(t.resolve_prefix("zzzzzz"), Err(CoreError::Registry(_))), "no match");
        assert!(matches!(t.resolve_prefix(""), Err(CoreError::Registry(_))), "empty id");
    }

    // --- the file backend + composed registry ---

    #[test]
    fn file_store_round_trip_and_absent_is_empty() {
        let home = tempfile::tempdir().unwrap();
        let store = FileStore::at(home.path());
        // Absent registry loads as empty.
        assert!(store.load().unwrap().tickets.is_empty());

        let reg = Registry::new(FileStore::at(home.path()));
        let now = Utc::now();
        let r = rec(now, None);
        let nonce = r.nonce;
        reg.issue(r).unwrap();
        assert!(reg.is_valid(&nonce, now).unwrap());
        reg.revoke(&nonce).unwrap();
        assert!(!reg.is_valid(&nonce, now).unwrap());
        assert_eq!(reg.list().unwrap().len(), 1, "revoke updates in place, not append");
        // The file exists and re-parses.
        assert!(store.path().is_file());
        assert_eq!(store.load().unwrap().tickets[0].nonce, nonce);
    }

    #[test]
    fn revoke_by_prefix_via_registry() {
        let home = tempfile::tempdir().unwrap();
        let reg = Registry::new(FileStore::at(home.path()));
        let now = Utc::now();
        let r = rec(now, None);
        let nonce = r.nonce;
        reg.issue(r).unwrap();
        let revoked = reg.revoke_by_prefix(&nonce.to_hex()[..8]).unwrap();
        assert_eq!(revoked, nonce);
        assert!(!reg.is_valid(&nonce, now).unwrap());
    }

    /// A concurrent send (issue) and revoke must never leave `issued.json` torn: a reader loading in
    /// a tight loop while writers hammer the file must never see a parse error (atomic rename).
    #[test]
    fn concurrent_writes_never_tear_the_file() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().to_path_buf();
        // Seed one record so revokers and readers have a well-formed file from the start.
        let seed = Registry::new(FileStore::at(&home_path));
        let seeded = rec(Utc::now(), None);
        let seeded_nonce = seeded.nonce;
        seed.issue(seeded).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        // Writers: issue fresh nonces and revoke the seed, concurrently.
        for _ in 0..4 {
            let p = home_path.clone();
            handles.push(std::thread::spawn(move || {
                let reg = Registry::new(FileStore::at(&p));
                for _ in 0..25 {
                    let _ = reg.issue(rec(Utc::now(), None));
                    let _ = reg.revoke(&seeded_nonce);
                }
            }));
        }

        // Reader: load in a tight loop; a torn file would surface as a parse error here.
        let p = home_path.clone();
        let stop_reader = stop.clone();
        let reader = std::thread::spawn(move || {
            let store = FileStore::at(&p);
            while !stop_reader.load(Ordering::Relaxed) {
                store.load().expect("issued.json must always parse — never torn");
            }
        });

        for h in handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        // Final state is well-formed.
        FileStore::at(&home_path).load().expect("final issued.json parses");
    }
}
