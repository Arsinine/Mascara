//! NIP-65 relay-list resolution + the first-contact bootstrap order (spec §Discovery,
//! §Relay Model). NIP-65 answers *"which relays hold this peer's events"*; a kind-10002 event
//! advertises a peer's read/write relays, self-published and signed, so there is no
//! transitive-trust list to poison.
//!
//! The chicken-and-egg of a never-seen `npub` (you don't yet know their relays) is closed by
//! [`bootstrap_order`]: prefer the peer's advertised relays when known, always falling back to
//! your seed + own relays — so first contact works before any relay-list is fetched.

use hb_core::Identity;
use nostr::nips::nip65;
use nostr::prelude::*;

use crate::error::NetError;

/// A peer's advertised relay set (NIP-65). A relay with no read/write marker counts as both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayList {
    /// Relays the peer reads from — where you publish events *to* them (DMs, etc.).
    pub read: Vec<String>,
    /// Relays the peer writes to — their "outbox", where you fetch their events *from*.
    pub write: Vec<String>,
}

/// Build a signed NIP-65 relay-list event (kind 10002) advertising `read` / `write` relays.
/// A relay present in both lists is emitted once with no marker (read+write).
pub fn build_relay_list(
    identity: &Identity,
    read: &[String],
    write: &[String],
) -> Result<Event, NetError> {
    let mut entries: Vec<(RelayUrl, Option<RelayMetadata>)> = Vec::new();
    for w in write {
        let url = RelayUrl::parse(w).map_err(|e| NetError::InvalidRelayList(e.to_string()))?;
        let meta = if read.contains(w) { None } else { Some(RelayMetadata::Write) };
        entries.push((url, meta));
    }
    for r in read {
        if write.contains(r) {
            continue; // already emitted as a read+write entry above
        }
        let url = RelayUrl::parse(r).map_err(|e| NetError::InvalidRelayList(e.to_string()))?;
        entries.push((url, Some(RelayMetadata::Read)));
    }
    Ok(identity.sign(EventBuilder::relay_list(entries))?)
}

/// Verify + parse a NIP-65 relay-list event into its read/write sets. The Schnorr signature and
/// the kind are checked first — a tampered or wrong-kind event is refused.
///
/// **Author pinning is the caller's job:** this verifies the event is *validly signed* by its
/// author, but a relay can return a validly-signed relay-list authored by someone else. A caller
/// resolving a *specific* peer must pin `event.pubkey` to that peer's npub (the resolution fetch
/// is already author-scoped, so this is belt-and-suspenders against a lying relay).
pub fn parse_relay_list(event: &Event) -> Result<RelayList, NetError> {
    event
        .verify()
        .map_err(|e| NetError::InvalidRelayList(format!("signature: {e}")))?;
    if event.kind != Kind::RelayList {
        return Err(NetError::InvalidRelayList(format!(
            "expected NIP-65 kind 10002, got {}",
            event.kind.as_u16()
        )));
    }
    let mut list = RelayList::default();
    for (url, meta) in nip65::extract_relay_list(event) {
        let s = url.to_string();
        match meta {
            None => {
                list.read.push(s.clone());
                list.write.push(s);
            }
            Some(RelayMetadata::Read) => list.read.push(s),
            Some(RelayMetadata::Write) => list.write.push(s),
        }
    }
    Ok(list)
}

/// The first-contact bootstrap order for *fetching a peer's events* (spec §Discovery).
///
/// Prefers the peer's advertised **write** relays (their outbox) when a NIP-65 list was found,
/// then always falls back to your `seed` and `own` relays — so a peer who follows the seed-relay
/// convention is still reachable when no relay-list exists yet. Order is preserved and
/// duplicates are collapsed.
pub fn bootstrap_order(seed: &[String], own: &[String], peer: Option<&RelayList>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(peer) = peer {
        extend_unique(&mut out, &peer.write);
    }
    extend_unique(&mut out, seed);
    extend_unique(&mut out, own);
    out
}

/// Append `relays` to `out`, skipping any already present (order-preserving dedup).
fn extend_unique(out: &mut Vec<String>, relays: &[String]) {
    for r in relays {
        if !out.contains(r) {
            out.push(r.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn relay_list_roundtrips_read_write_and_both() {
        let id = Identity::generate();
        let read = s(&["wss://read-only.example", "wss://both.example"]);
        let write = s(&["wss://write-only.example", "wss://both.example"]);
        let ev = build_relay_list(&id, &read, &write).unwrap();
        let parsed = parse_relay_list(&ev).unwrap();
        // The "both" relay appears in each set; markered ones in exactly one.
        assert!(parsed.write.iter().any(|r| r.contains("write-only")));
        assert!(parsed.read.iter().any(|r| r.contains("read-only")));
        assert!(parsed.write.iter().any(|r| r.contains("both")));
        assert!(parsed.read.iter().any(|r| r.contains("both")));
    }

    #[test]
    fn nip65_selects_peer_advertised_relays() {
        // When a peer's NIP-65 is known, their advertised outbox leads the query order.
        let peer = RelayList { read: s(&["wss://peer-read"]), write: s(&["wss://peer-outbox"]) };
        let order = bootstrap_order(&s(&["wss://seed"]), &s(&["wss://own"]), Some(&peer));
        assert_eq!(order.first().unwrap(), "wss://peer-outbox", "advertised relays lead");
        // Seeds remain present as a fallback tail.
        assert!(order.contains(&"wss://seed".to_string()));
    }

    #[test]
    fn nip65_bootstrap_falls_back_to_seeds() {
        // No relay-list found → fall back to seed + own (seed first), deduped.
        let order = bootstrap_order(&s(&["wss://seed1", "wss://seed2"]), &s(&["wss://seed1"]), None);
        assert_eq!(order, s(&["wss://seed1", "wss://seed2"]), "seed leads, duplicate own collapsed");
    }

    #[test]
    fn parse_rejects_wrong_kind() {
        let id = Identity::generate();
        let ev = id.sign(EventBuilder::new(Kind::TextNote, "not a relay list")).unwrap();
        assert!(matches!(parse_relay_list(&ev), Err(NetError::InvalidRelayList(_))));
    }

    #[test]
    fn parse_rejects_tampered_event() {
        // A relay that mutates the event after signing is caught on verify (id mismatch).
        let id = Identity::generate();
        let mut ev = build_relay_list(&id, &s(&["wss://r"]), &s(&["wss://w"])).unwrap();
        ev.content = "tampered".into();
        match parse_relay_list(&ev) {
            Err(NetError::InvalidRelayList(m)) => assert!(m.contains("signature"), "got: {m}"),
            other => panic!("expected a signature failure, got {other:?}"),
        }
    }
}
