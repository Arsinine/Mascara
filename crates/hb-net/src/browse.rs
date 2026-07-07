//! The M3 application value loop — **publish → discover → browse** — composed over the M2 client
//! and M1 core. This is *application orchestration*, deliberately placed in `hb-net` (M3 decision
//! #1, option a) so the `hb-it` L2 suite drives the **real production code** `hb-app` will call,
//! not a parallel reimplementation. The pure pieces it leans on live in sibling modules
//! (`render`, `cache`, `discover`) so they stay unit-testable without a relay; the async functions
//! here are proven end-to-end at L2.
//!
//! A browse is a **relay read + a local decrypt** — it composes only `RelayClient::fetch` and
//! `hb-core` parsers, and **never** touches iroh or any peer socket (AB10). The browse-key gates
//! the listing: a follow-only share code (bare `npub`) yields the teaser only; a wrong browse-key
//! yields the teaser with the listing locked (decrypt fails cleanly, not a hard browse error).

use std::collections::HashMap;
use std::time::Duration;

use hb_core::event::{
    build_listing_event, parse_listing_event, parse_teaser, Teaser, KIND_LISTING, KIND_TEASER,
};
use hb_core::listing::BrowseKey;
use hb_core::{Identity, ShareCode};
use nostr::prelude::*;

use crate::client::{teaser_search_filter, RelayClient};
use crate::discover::{ingest_teasers, select_newest_by_created_at, SearchHit};
use crate::error::NetError;
use crate::nip65::{bootstrap_order, parse_relay_list};
use crate::render::{render_listing, RenderedListing};
use crate::split::split_listing;

/// Parse a pasted share code, surfacing `hb-core`'s codec rejection as a `NetError`. A bare `npub`
/// is follow-only (no browse-key); a full `hbk1…` carries the browse-key; anything malformed
/// (non-bech32, corrupt bytes, truncated, wrong version) returns a clean `Err`, never a panic.
pub fn parse_share_code(s: &str) -> Result<ShareCode, NetError> {
    Ok(ShareCode::parse(s)?)
}

/// The outcome of publishing a (possibly split) listing.
#[derive(Debug, Clone)]
pub struct PublishedListing {
    /// How many parts were published (1 = unsplit; >1 = index + content parts).
    pub parts: usize,
}

/// Publish a collection listing: encrypt under `browse_key`, split per-folder when it exceeds
/// `max_bytes`, and publish the index + every content part as parameterized-replaceable events
/// (re-publishing the same slug supersedes the prior listing — N3). Re-keying is just supplying a
/// fresh `browse_key` here (the per-collection symmetric key, not the `npub` identity).
pub async fn publish_listing(
    client: &RelayClient,
    identity: &Identity,
    slug: &str,
    browse_key: &BrowseKey,
    listing_json: &str,
    max_bytes: usize,
) -> Result<PublishedListing, NetError> {
    let parts = split_listing(slug, listing_json, max_bytes)?;
    for part in &parts {
        let event = build_listing_event(identity, &part.d_tag, browse_key, &part.json)?;
        client.publish(&event).await?;
    }
    Ok(PublishedListing { parts: parts.len() })
}

/// The result of browsing a share code: the peer's public teaser (if any), the decrypted listing
/// tree (if a browse-key was held and the listing decrypted), and the NIP-65-resolved relay order
/// the browse used (DISC2 evidence).
#[derive(Debug, Clone)]
pub struct BrowseResult {
    pub teaser: Option<Teaser>,
    pub listing: Option<RenderedListing>,
    pub resolved_relays: Vec<String>,
}

/// Resolve where a peer's events live (NIP-65 first-contact bootstrap, spec §Discovery): fetch the
/// peer's kind-10002 relay list, **pin it to the peer's npub** (a lying relay can't substitute
/// someone else's list), and order via [`bootstrap_order`] — peer outbox first, then seed + own.
/// `bootstrap_order` only *orders*; this function does the NIP-65 fetch itself.
pub async fn resolve_peer_relays(
    client: &RelayClient,
    peer: &PublicKey,
    seed: &[String],
    own: &[String],
    timeout: Duration,
) -> Vec<String> {
    let peer_list = match client.fetch(Filter::new().author(*peer).kind(Kind::RelayList), timeout).await
    {
        // Author-pin, then pick the **newest** relay-list (a non-compliant relay may return more
        // than one kind-10002 for an author — the latest is authoritative, never the first seen).
        Ok(events) => {
            let pinned: Vec<Event> = events.into_iter().filter(|e| &e.pubkey == peer).collect();
            select_newest_by_created_at(pinned).and_then(|e| parse_relay_list(&e).ok())
        }
        Err(_) => None,
    };
    bootstrap_order(seed, own, peer_list.as_ref())
}

/// Browse a share code as a pure relay read. Always returns the teaser when present; the listing is
/// `None` for a follow-only code or when the held browse-key can't decrypt it (locked, not an
/// error). `seed`/`own` seed the NIP-65 bootstrap.
pub async fn browse_share_code(
    client: &RelayClient,
    share_code: &ShareCode,
    slug: &str,
    seed: &[String],
    own: &[String],
    timeout: Duration,
) -> Result<BrowseResult, NetError> {
    let peer = share_code.pubkey();
    let resolved_relays = resolve_peer_relays(client, &peer, seed, own, timeout).await;
    // **Act on** the NIP-65 resolution: connect to the peer's advertised outbox before fetching, so
    // a peer who publishes only to their own relays (not the caller's seed set) is still reachable.
    let _ = client.ensure_relays(&resolved_relays, timeout).await;

    // Teaser (public): newest by created_at, then verify+parse.
    let teaser_events =
        client.fetch(Filter::new().author(peer).kind(Kind::from_u16(KIND_TEASER)), timeout).await?;
    let teaser = select_newest_by_created_at(teaser_events).and_then(|e| parse_teaser(&e).ok());

    // Listing (gated by the browse-key): a decrypt failure locks the listing without failing the
    // whole browse — the teaser still shows (BR1).
    let listing = match share_code.browse_key() {
        Some(bk) => fetch_listing(client, &peer, slug, &bk, timeout).await.ok(),
        None => None,
    };

    Ok(BrowseResult { teaser, listing, resolved_relays })
}

/// Fetch a slug's listing family (index + content parts), pick the newest event per `d`-tag (so a
/// non-compliant relay's stale replaceable duplicate can't win — N3/AB8), decrypt each with the
/// browse-key (which re-verifies the Schnorr signature), and render into a possibly-partial tree.
async fn fetch_listing(
    client: &RelayClient,
    peer: &PublicKey,
    slug: &str,
    browse_key: &BrowseKey,
    timeout: Duration,
) -> Result<RenderedListing, NetError> {
    // M4 optimisation: this fetches all of the peer's listing events and filters to the slug family
    // client-side. A two-phase fetch (the `d=slug` index first, then exactly its `d=slug#partI`
    // parts) would avoid pulling a prolific author's other collections — deferred (the read-side
    // `MAX_LISTING_PARTS` cap bounds the worst case regardless).
    let events =
        client.fetch(Filter::new().author(*peer).kind(Kind::from_u16(KIND_LISTING)), timeout).await?;

    let part_prefix = format!("{slug}#part");
    let mut by_d: HashMap<String, Vec<Event>> = HashMap::new();
    for ev in events {
        if let Some(d) = ev.tags.identifier() {
            if d == slug || d.starts_with(&part_prefix) {
                by_d.entry(d.to_string()).or_default().push(ev);
            }
        }
    }
    if by_d.is_empty() {
        return Err(NetError::Split(format!("no listing found for slug '{slug}'")));
    }

    let mut payloads: Vec<String> = Vec::new();
    for (_d, group) in by_d {
        if let Some(ev) = select_newest_by_created_at(group) {
            let (_slug, json) = parse_listing_event(&ev, browse_key)?;
            payloads.push(json);
        }
    }
    render_listing(&payloads)
}

/// Discover peers by tag-search over public teasers: build the filter (empty∧empty → `Err`,
/// DISC4), fetch, then ingest — bound size, discard bad-sig, AND-tags / OR-content-types, dedup by
/// `npub`, cap (AB3/DISC1). A hit yields the teaser only, never a listing (DISC3).
pub async fn search_teasers(
    client: &RelayClient,
    tags: &[String],
    content_types: &[String],
    cap: usize,
    timeout: Duration,
) -> Result<Vec<SearchHit>, NetError> {
    let filter = teaser_search_filter(tags, content_types)?;
    let events = client.fetch(filter, timeout).await?;
    Ok(ingest_teasers(events, tags, content_types, cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ShareCode deliberately has no Debug (it holds the secret browse-key), so unwrap its parse
    // through a match rather than `.unwrap()`.
    fn ok(s: &str) -> ShareCode {
        match parse_share_code(s) {
            Ok(p) => p,
            Err(e) => panic!("expected a valid share code, got {e}"),
        }
    }

    #[test]
    fn full_sharecode_yields_browse_key() {
        let pk = Identity::generate().public_key();
        let bk: [u8; 32] = [7; 32];
        let code = ShareCode::Full { pubkey: pk, browse_key: bk }.encode().unwrap();
        let parsed = ok(&code);
        assert_eq!(parsed.browse_key(), Some(bk), "a full code unlocks the browse-key");
        assert_eq!(parsed.pubkey(), pk);
    }

    #[test]
    fn bare_npub_is_follow_only_no_browse() {
        let id = Identity::generate();
        let parsed = ok(&id.npub());
        assert_eq!(parsed.browse_key(), None, "a bare npub is follow-only");
        assert_eq!(parsed.pubkey(), id.public_key());
    }

    #[test]
    fn malformed_sharecode_rejected_with_reason() {
        // Non-bech32, truncated, and garbage all return a clean Err (never a panic) — the
        // orchestration surfaces hb-core's codec rejection.
        for s in ["not-a-code", "npub1", "hbk1zzzz", "", "::::"] {
            match parse_share_code(s) {
                Err(e) => assert!(!e.to_string().is_empty(), "{s:?} must reject with a reason"),
                Ok(_) => panic!("{s:?} should not parse as a valid share code"),
            }
        }
    }
}
