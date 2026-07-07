//! The local snapshot **cache-policy** core (M3): the pure decision of whether a browse serves a
//! cached listing or refetches from a relay. The filesystem read/write is a thin `hb-app` adapter;
//! only this policy is here, so it is unit-tested without I/O.
//!
//! Two invariants the policy encodes, both adversarial:
//!
//! - **Freshness is measured by *local fetch-time*, never the relay event's `created_at`.** A
//!   hostile relay can forge a far-future `created_at` to pin stale (or malicious) data as
//!   permanently "fresh"; the client's own clock at fetch time cannot be forged. So
//!   [`cache_decision`] takes only `fetched_at` — `created_at` is structurally absent from the
//!   decision and cannot poison it.
//! - **A re-key kills *new* listings, not the cache (AB9).** After a peer rotates a collection's
//!   browse-key, the old key can't decrypt newly-published events — but plaintext already decrypted
//!   and cached stays readable (it's just data, no key needed to read it). Each entry records the
//!   `browse_key_era` it was decrypted under, so the provenance is explicit.

/// How long a fetched listing is considered fresh before a browse refetches it. A listing changes
/// far less often than presence, but staleness should still bound silent divergence.
pub const CACHE_FRESH_SECS: u64 = 600;

/// A cached, already-decrypted listing snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct CachedListing {
    pub slug: String,
    /// The decrypted, restitched plaintext — always readable, no key required.
    pub listing_json: String,
    /// The **local** unix time the client fetched this — the freshness basis (never `created_at`).
    pub fetched_at: u64,
    /// The browse-key this plaintext was decrypted under (AB9 provenance).
    pub browse_key_era: [u8; 32],
}

/// Whether a browse should serve the cached entry or go to a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheDecision {
    /// Fresh enough — serve the cached plaintext, no relay round-trip.
    ServeCached,
    /// Stale or absent — refetch from a relay.
    Refetch,
}

/// The cache-policy decision. Note the signature carries **no `created_at`** — freshness is the
/// client-local `now - fetched_at`, so a forged event timestamp cannot extend it.
pub fn cache_decision(entry: Option<&CachedListing>, now: u64, ttl: u64) -> CacheDecision {
    match entry {
        Some(e) if now.saturating_sub(e.fetched_at) <= ttl => CacheDecision::ServeCached,
        _ => CacheDecision::Refetch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fetched_at: u64, era: u8) -> CachedListing {
        CachedListing {
            slug: "criterion".into(),
            listing_json: r#"{"slug":"criterion","entries":[{"name":"Ran"}]}"#.into(),
            fetched_at,
            browse_key_era: [era; 32],
        }
    }

    #[test]
    fn fresh_cache_served_without_relay() {
        let now = 1_000_000;
        let e = entry(now - 10, 1); // fetched 10s ago, well within the window
        assert_eq!(cache_decision(Some(&e), now, CACHE_FRESH_SECS), CacheDecision::ServeCached);
    }

    #[test]
    fn stale_cache_triggers_refetch() {
        let now = 1_000_000;
        let e = entry(now - CACHE_FRESH_SECS - 1, 1); // one second past the window
        assert_eq!(cache_decision(Some(&e), now, CACHE_FRESH_SECS), CacheDecision::Refetch);
    }

    #[test]
    fn cache_miss_falls_through_to_relay() {
        assert_eq!(cache_decision(None, 1_000_000, CACHE_FRESH_SECS), CacheDecision::Refetch);
    }

    #[test]
    fn rekey_old_plaintext_cache_still_readable() {
        // AB9: a peer re-keyed (the "current" era is now [9;32]). A snapshot cached under the OLD
        // era is still readable plaintext — reading it needs no key — and the policy still serves
        // it while fresh. The leaked old key dying applies to *new* fetches, not cached plaintext.
        let now = 1_000_000;
        let old = entry(now - 10, 1);
        let current_era = [9u8; 32];
        assert_ne!(old.browse_key_era, current_era, "the peer has since re-keyed");
        // The cached plaintext is intact and readable without any key.
        assert!(old.listing_json.contains("Ran"));
        assert_eq!(cache_decision(Some(&old), now, CACHE_FRESH_SECS), CacheDecision::ServeCached);
    }

    #[test]
    fn future_dated_event_does_not_extend_freshness() {
        // A hostile relay served an event claiming a far-future created_at, but freshness is keyed
        // on the client's local fetch-time. The entry was fetched long ago → it is stale and
        // refetched, regardless of any timestamp the event carried (which isn't even a parameter).
        let now = 2_000_000;
        let stale_by_local_clock = entry(now - CACHE_FRESH_SECS - 5_000, 1);
        assert_eq!(
            cache_decision(Some(&stale_by_local_clock), now, CACHE_FRESH_SECS),
            CacheDecision::Refetch,
            "freshness must derive from local fetch-time, not a forgeable created_at"
        );
    }
}
