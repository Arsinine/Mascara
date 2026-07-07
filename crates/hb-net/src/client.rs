//! The multi-relay Nostr client (spec §Relay Model, §Discovery). Ports and hardens the M0
//! spike's proven `Client::builder → add_relay → try_connect → send_event → fetch_events`
//! sequence into the production client `hb-it` drives now and `hb-app` will drive in M4.
//!
//! Two disciplines from M0 are load-bearing: `connect()` returns *before* the websocket
//! handshake, so we always `try_connect` and refuse to proceed if no relay came up; and a
//! relay's per-event accept/reject is surfaced (the `Output.success`/`failed` split) so a
//! silent drop or an explicit `OK: false` is observable (AB8), never swallowed.

use std::collections::HashSet;
use std::time::Duration;

use hb_core::Identity;
use nostr_sdk::prelude::*;

use crate::error::NetError;

/// A connected multi-relay client.
pub struct RelayClient {
    client: Client,
    relays: Vec<String>,
}

/// Per-relay accept/reject split for a single publish.
#[derive(Debug, Clone)]
pub struct PublishOutcome {
    /// Relays that accepted the event (`OK: true`).
    pub accepted: Vec<String>,
    /// Relays that rejected it, with the reason string they returned.
    pub rejected: Vec<(String, String)>,
}

impl RelayClient {
    /// Connect to `relays`, waiting up to `timeout` for the websocket handshake. Fails if **no**
    /// relay completed the handshake — publishing against an unconnected relay silently fails
    /// with "relay not connected" (the M0 finding), so we never proceed half-connected.
    pub async fn connect(
        identity: &Identity,
        relays: &[String],
        timeout: Duration,
    ) -> Result<Self, NetError> {
        if relays.is_empty() {
            return Err(NetError::NoRelayConnected("no relays configured".into()));
        }
        let client = Client::builder().signer(identity.keys().clone()).build();
        for r in relays {
            client
                .add_relay(r.as_str())
                .await
                .map_err(|e| NetError::Client(format!("add_relay({r}): {e}")))?;
        }
        let conn = client.try_connect(timeout).await;
        if conn.success.is_empty() {
            return Err(NetError::NoRelayConnected(format!("{:?}", conn.failed)));
        }
        Ok(Self { client, relays: relays.to_vec() })
    }

    /// Publish a pre-signed hb-core event to every write-relay, returning the per-relay
    /// accept/reject split. Errors only if **no** relay accepted (an all-reject / all-drop).
    pub async fn publish(&self, event: &Event) -> Result<PublishOutcome, NetError> {
        let output = self
            .client
            .send_event(event)
            .await
            .map_err(|e| NetError::Client(format!("send_event(kind {}): {e}", event.kind.as_u16())))?;
        let outcome = PublishOutcome {
            accepted: output.success.iter().map(|u| u.to_string()).collect(),
            rejected: output.failed.iter().map(|(u, why)| (u.to_string(), why.clone())).collect(),
        };
        if outcome.accepted.is_empty() {
            return Err(NetError::PublishRejected(format!("{:?}", outcome.rejected)));
        }
        Ok(outcome)
    }

    /// Fetch events by `filter`, **deduped by event id** across the relay set (a peer's event
    /// pulled from two relays collapses to one). A filter constraining nothing is refused before
    /// the query — an unbounded fetch is never issued.
    pub async fn fetch(&self, filter: Filter, timeout: Duration) -> Result<Vec<Event>, NetError> {
        if filter.is_empty() {
            return Err(NetError::EmptyFilter);
        }
        let events = self
            .client
            .fetch_events(filter, timeout)
            .await
            .map_err(|e| NetError::Client(e.to_string()))?;
        Ok(dedup_by_id(events))
    }

    /// The relay set passed to `connect`. (Relays added later via `ensure_relays` are connected on
    /// the underlying client but not recorded here — this getter reports the initial configured set.)
    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// Ensure the client is connected to every relay in `relays`, adding + connecting any not in the
    /// configured set. This is how the browse flow **acts on** NIP-65 resolution — connecting to a
    /// peer's advertised outbox before fetching their events, so a peer who publishes only to their
    /// own relays is still reachable. Best-effort and idempotent: a relay that fails to connect is
    /// skipped (existing connections keep working); `add_relay` is a no-op for already-known relays.
    pub async fn ensure_relays(&self, relays: &[String], timeout: Duration) -> Result<(), NetError> {
        let mut added = false;
        for r in relays {
            if !self.relays.contains(r) && self.client.add_relay(r.as_str()).await.is_ok() {
                added = true;
            }
        }
        if added {
            // Connect the newly-added relays; already-connected ones are unaffected.
            let _ = self.client.try_connect(timeout).await;
        }
        Ok(())
    }

    /// Close all relay connections.
    pub async fn disconnect(self) {
        self.client.disconnect().await;
    }
}

/// Collapse events sharing an id to a single occurrence, preserving first-seen order — the
/// multi-relay dedup invariant (a hostile or redundant relay returning a duplicate can't inflate
/// results). Pure, so it is unit-tested without a relay.
pub fn dedup_by_id<I>(events: I) -> Vec<Event>
where
    I: IntoIterator<Item = Event>,
{
    let mut seen: HashSet<EventId> = HashSet::new();
    events.into_iter().filter(|e| seen.insert(e.id)).collect()
}

/// Build a teaser tag-search filter. Refused before any query (DISC4) when it constrains
/// nothing — empty tags **and** empty content-types. The relay returns the OR-union of all
/// `#t` terms; the caller intersects tags / unions content-types client-side (DISC1).
pub fn teaser_search_filter(
    tags: &[String],
    content_types: &[String],
) -> Result<Filter, NetError> {
    if tags.is_empty() && content_types.is_empty() {
        return Err(NetError::EmptyFilter);
    }
    let all: Vec<String> = tags.iter().chain(content_types).cloned().collect();
    Ok(Filter::new()
        .kind(Kind::from_u16(hb_core::event::KIND_TEASER))
        .hashtags(all))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hb_core::event::{build_teaser, Teaser};

    fn ev(name: &str) -> Event {
        let id = Identity::generate();
        build_teaser(
            &id,
            &Teaser {
                display_name: name.into(),
                bio: String::new(),
                tags: vec!["anime".into()],
                content_types: vec!["video".into()],
            },
        )
        .unwrap()
    }

    #[test]
    fn dedup_collapses_same_id_across_relays() {
        let a = ev("a");
        let b = ev("b");
        // The same event fetched from two relays + a distinct one → two unique.
        let deduped = dedup_by_id(vec![a.clone(), a.clone(), b.clone()]);
        assert_eq!(deduped.len(), 2);
        assert!(deduped.iter().any(|e| e.id == a.id));
        assert!(deduped.iter().any(|e| e.id == b.id));
    }

    #[test]
    fn dedup_preserves_first_seen_order() {
        let a = ev("a");
        let b = ev("b");
        let deduped = dedup_by_id(vec![a.clone(), b.clone(), a.clone()]);
        assert_eq!(deduped[0].id, a.id);
        assert_eq!(deduped[1].id, b.id);
    }

    #[test]
    fn empty_filter_rejected_before_query() {
        // DISC4: empty tags AND empty content-types is refused before any relay query.
        assert!(matches!(teaser_search_filter(&[], &[]), Err(NetError::EmptyFilter)));
    }

    #[test]
    fn teaser_filter_constrains_kind_and_tags() {
        let f = teaser_search_filter(&["anime".into()], &["video".into()]).unwrap();
        assert!(!f.is_empty(), "a constrained filter is not empty");
    }
}
