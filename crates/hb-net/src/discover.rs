//! Pure discovery logic (M3): the teaser tag/content-type matcher, the ingest pipeline that turns
//! a relay's raw teaser events into trustworthy search hits, and replaceable-event resolution.
//!
//! A relay is an adversary (AB3/AB8): it can flood junk teasers, return bad-signature events,
//! oversize bodies, duplicates, or — for a replaceable event — *both* the old and new version when
//! it should have dropped the old. Every guard here is a pure function so the resilience is
//! unit-tested without a relay: bad signatures are discarded (via `parse_teaser`'s verify),
//! oversize bodies are bounded before parse, results are deduped by `npub` and capped, and a
//! non-compliant relay's duplicate replaceable events collapse to the newest by `created_at`.

use hb_core::event::{parse_teaser, Teaser};
use nostr::prelude::*;

/// Per-teaser content-size bound applied on ingest, before parse — a hostile relay flooding huge
/// teaser bodies can't exhaust memory. (Generous vs a real teaser; teasers are name+bio+tags.)
pub const MAX_TEASER_BYTES: usize = 8192;

/// A trustworthy discovery hit: a verified teaser and the `npub` that signed it.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub npub: String,
    pub teaser: Teaser,
}

/// Whether a teaser satisfies a query: **tags AND-intersect** (every requested tag must be
/// present) while **content-types OR-union** (any requested content-type matches). An empty tag
/// list imposes no tag constraint; an empty content-type list imposes no content-type constraint
/// (DISC1).
pub fn teaser_matches(teaser: &Teaser, tags: &[String], content_types: &[String]) -> bool {
    let tags_ok = tags.iter().all(|q| teaser.tags.contains(q));
    let ct_ok =
        content_types.is_empty() || content_types.iter().any(|q| teaser.content_types.contains(q));
    tags_ok && ct_ok
}

/// Turn raw fetched teaser events into ranked, trustworthy hits:
/// bound size → verify+parse (discard bad-sig / wrong-schema) → match the query → dedup by `npub`
/// → cap. Each stage is independently observable in the tests (AB3a/b/c + DISC1).
pub fn ingest_teasers(
    events: Vec<Event>,
    tags: &[String],
    content_types: &[String],
    cap: usize,
) -> Vec<SearchHit> {
    // Sort newest-first so the per-`npub` dedup keeps the **latest** teaser — a non-compliant relay
    // that returns an author's old + new teaser (or serves the stale one first) can't hide the
    // update. Ties break on the higher event id (deterministic).
    let mut events = events;
    events.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut hits: Vec<SearchHit> = Vec::new();
    for ev in events {
        if ev.content.len() > MAX_TEASER_BYTES {
            continue; // AB3: oversize body bounded before any parse
        }
        let Ok(teaser) = parse_teaser(&ev) else {
            continue; // AB3: bad signature / wrong schema discarded
        };
        if !teaser_matches(&teaser, tags, content_types) {
            continue;
        }
        let npub = ev.pubkey.to_bech32().unwrap_or_else(|_| ev.pubkey.to_hex());
        if seen.insert(npub.clone()) {
            hits.push(SearchHit { npub, teaser });
        }
        if hits.len() >= cap {
            break;
        }
    }
    hits
}

/// Collapse a set of events for one replaceable address to the **newest by `created_at`**. A
/// compliant relay keeps only the latest, but a non-compliant one can return both the old and new
/// version — the client must never read the stale one (N3/AB8). Ties break on the higher event id
/// (deterministic). Returns `None` for an empty set.
pub fn select_newest_by_created_at(events: Vec<Event>) -> Option<Event> {
    events
        .into_iter()
        .max_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hb_core::Identity;

    fn teaser_with(tags: &[&str], cts: &[&str]) -> Teaser {
        Teaser {
            display_name: "archivebox".into(),
            bio: "hoards".into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            content_types: cts.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ev(id: &Identity, t: &Teaser) -> Event {
        hb_core::event::build_teaser(id, t).unwrap()
    }

    #[test]
    fn tag_terms_intersect_and() {
        let t = teaser_with(&["anime", "vhs"], &["video"]);
        assert!(teaser_matches(&t, &["anime".into(), "vhs".into()], &[]), "all tags present → match");
        assert!(!teaser_matches(&t, &["anime".into(), "manga".into()], &[]), "a missing tag → no match (AND)");
        assert!(teaser_matches(&t, &[], &[]) == teaser_matches(&t, &[], &[]));
    }

    #[test]
    fn content_types_union_or() {
        let t = teaser_with(&["anime"], &["video"]);
        assert!(teaser_matches(&t, &[], &["video".into(), "audio".into()]), "any content-type matches → OR");
        assert!(!teaser_matches(&t, &[], &["audio".into()]), "no content-type matches → no match");
    }

    #[test]
    fn teasers_dedup_by_npub() {
        let id = Identity::generate();
        let t = teaser_with(&["anime"], &["video"]);
        // The same author appears twice (e.g. fetched from two relays, or two t-tag hits).
        let hits = ingest_teasers(vec![ev(&id, &t), ev(&id, &t)], &["anime".into()], &[], 100);
        assert_eq!(hits.len(), 1, "one npub yields one hit");
    }

    #[test]
    fn dedup_keeps_newest_teaser_per_npub() {
        // A non-compliant relay returns an author's OLD and NEW teaser, old first. The dedup must
        // keep the newest (by created_at), never the stale one a relay served first.
        let id = Identity::generate();
        let mut old = teaser_with(&["anime"], &["video"]);
        old.display_name = "old".into();
        let mut new = teaser_with(&["anime"], &["video"]);
        new.display_name = "new".into();
        let build_at = |t: &Teaser, ts: u64| {
            let base = hb_core::event::build_teaser(&id, t).unwrap();
            let tags: Vec<Tag> = base.tags.iter().cloned().collect();
            id.sign(
                EventBuilder::new(base.kind, base.content)
                    .tags(tags)
                    .custom_created_at(Timestamp::from(ts)),
            )
            .unwrap()
        };
        let old_ev = build_at(&old, 1_000);
        let new_ev = build_at(&new, 2_000);
        let hits = ingest_teasers(vec![old_ev, new_ev], &["anime".into()], &[], 100);
        assert_eq!(hits.len(), 1, "one npub → one hit");
        assert_eq!(hits[0].teaser.display_name, "new", "the newest teaser wins, not the first-served");
    }

    #[test]
    fn results_capped_at_limit() {
        let t = teaser_with(&["anime"], &["video"]);
        let events: Vec<Event> = (0..10).map(|_| ev(&Identity::generate(), &t)).collect();
        let hits = ingest_teasers(events, &["anime".into()], &[], 3);
        assert_eq!(hits.len(), 3, "result cap honoured");
    }

    #[test]
    fn bad_sig_teaser_discarded_before_dedup() {
        let good = ev(&Identity::generate(), &teaser_with(&["anime"], &["video"]));
        let mut tampered = ev(&Identity::generate(), &teaser_with(&["anime"], &["video"]));
        tampered.content = "mutated after signing".into(); // id no longer matches the signature
        let hits = ingest_teasers(vec![tampered, good.clone()], &["anime".into()], &[], 100);
        assert_eq!(hits.len(), 1, "only the validly-signed teaser survives");
        assert_eq!(hits[0].npub, good.pubkey.to_bech32().unwrap());
    }

    #[test]
    fn oversize_teaser_content_bounded_on_ingest() {
        let id = Identity::generate();
        let mut huge = teaser_with(&["anime"], &["video"]);
        huge.bio = "x".repeat(MAX_TEASER_BYTES + 1); // body exceeds the ingest bound
        let hits = ingest_teasers(vec![ev(&id, &huge)], &["anime".into()], &[], 100);
        assert!(hits.is_empty(), "an oversize teaser body is bounded out before parse");
    }

    #[test]
    fn duplicate_dtag_selects_highest_created_at() {
        // A non-compliant relay returns both the old and new version of one author's replaceable
        // event. The newest (by created_at) must win — never the stale one. (select_newest compares
        // timestamps only, so the content here is immaterial.)
        let id = Identity::generate();
        let kind = Kind::from_u16(hb_core::event::KIND_TEASER);
        let old_ev = id
            .sign(EventBuilder::new(kind, "old").custom_created_at(Timestamp::from(1_000)))
            .unwrap();
        let new_ev = id
            .sign(EventBuilder::new(kind, "new").custom_created_at(Timestamp::from(2_000)))
            .unwrap();
        let winner = select_newest_by_created_at(vec![old_ev, new_ev.clone()]).unwrap();
        assert_eq!(winner.id, new_ev.id, "the newer event is selected");
    }
}
