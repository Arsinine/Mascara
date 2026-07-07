//! Presence: the signed `npub`→iroh-node binding, with the node **address sealed** under the
//! account browse-key (spec §Data Model → "Encrypted presence node-address"; M4 decision #4).
//!
//! Replaces the legacy HTTP keepalive push. The app republishes a fresh, sealed presence binding to the
//! configured relays on a ~5-minute cadence; the public `npub`→node binding + `expires_at` stay
//! plaintext-verifiable (online-status freshness), while only a share-code (browse-key) holder can
//! unseal the dialable address.

use std::time::Duration;

use anyhow::{anyhow, Result};
use hb_core::{build_binding, BrowseKey, Identity};
use hb_net::RelayClient;
use nostr::prelude::*;

use crate::identity_state::SharedIdentity;
use crate::store::DataStore;
use crate::SharedEndpoint;

/// Binding validity window. Presence refreshes every ~5 min, so 30 min is a generous backstop
/// (and well within the `MAX_BINDING_TTL_SECS` cap hb-core enforces).
pub const PRESENCE_TTL_SECS: u64 = 30 * 60;
/// Republish cadence.
pub const PRESENCE_REFRESH_SECS: u64 = 5 * 60;
/// First publish fires shortly after launch (the endpoint needs a moment to bind).
const PRESENCE_FIRST_DELAY_SECS: u64 = 15;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build + publish a sealed presence binding for the current endpoint address. The sealed payload
/// is the serialized iroh `EndpointAddr` (id + transport addrs); only a browse-key holder unseals
/// it (`transfer::resolve_peer_addr`).
pub(crate) async fn publish_presence(
    client: &RelayClient,
    identity: &Identity,
    iroh_node_key: &[u8; 32],
    endpoint_addr_json: &str,
    browse_key: &BrowseKey,
) -> Result<()> {
    let addrs = vec![endpoint_addr_json.to_string()];
    let event = build_binding(identity, iroh_node_key, &addrs, browse_key, unix_now(), PRESENCE_TTL_SECS)
        .map_err(|e| anyhow!("build presence binding: {e}"))?;
    client.publish(&event).await.map_err(|e| anyhow!("publish presence: {e}"))?;
    Ok(())
}

/// Fetch a peer's newest presence event (kind 11111, author-pinned). The caller verifies the
/// binding (`transfer::resolve_peer_addr` / `hb-core::verify_binding`) before trusting it.
pub(crate) async fn fetch_peer_presence(
    client: &RelayClient,
    peer: &PublicKey,
    timeout: Duration,
) -> Result<Option<Event>> {
    let events = client
        .fetch(Filter::new().author(*peer).kind(Kind::from_u16(hb_core::binding::KIND_PRESENCE)), timeout)
        .await
        .map_err(|e| anyhow!("fetch presence: {e}"))?;
    Ok(hb_net::select_newest_by_created_at(events))
}

/// Background loop: republish presence on a fixed cadence while an identity + bound endpoint exist.
/// Replaces the legacy keepalive task. Best-effort — a missing relay/endpoint just skips the
/// cycle. `false` on the cancel channel wakes it early; `true` shuts it down.
pub(crate) async fn run_presence_loop(
    identity: SharedIdentity,
    endpoint_state: SharedEndpoint,
    store: DataStore,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut delay = Duration::from_secs(PRESENCE_FIRST_DELAY_SECS);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    tracing::debug!("presence loop cancelled");
                    break;
                }
            }
        }
        delay = Duration::from_secs(PRESENCE_REFRESH_SECS);

        // Snapshot the identity (clone the secp256k1 key) and node key without holding the lock
        // across the network call.
        let snapshot = {
            let guard = identity.read().await;
            guard.as_ref().map(|id| (id.identity.clone(), id.iroh_node_key(), id.browse_key))
        };
        let Some((id, node_key, browse_key)) = snapshot else { continue };

        let addr_json = {
            let ep_guard = endpoint_state.read().await;
            ep_guard.as_ref().and_then(|ep| serde_json::to_string(&ep.addr()).ok())
        };
        let Some(addr_json) = addr_json else { continue };

        match crate::net::connect(&id, &store).await {
            Ok(client) => {
                if let Err(e) = publish_presence(&client, &id, &node_key, &addr_json, &browse_key).await {
                    tracing::debug!("presence publish failed: {e}");
                }
                client.disconnect().await;
            }
            Err(e) => tracing::debug!("presence: no relay this cycle ({e})"),
        }
    }
}
