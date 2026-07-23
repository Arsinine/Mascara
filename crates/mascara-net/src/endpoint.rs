//! Build the iroh `Endpoint` (DESIGN §1/§6, MAS-INV-3), and map between it and the ticket's
//! network-agnostic [`mascara_core::Endpoint`] (DESIGN §3).
//!
//! **Discovery is off both directions BY CONSTRUCTION** — every endpoint here is built on
//! [`iroh::endpoint::presets::Minimal`], which has **zero address-lookup services**: nothing is
//! ever published, and `connect` performs no lookup. `presets::N0` (which adds pkarr/DNS) is
//! never used, and `.address_lookup(...)` is never called — this is the M2 form of
//! `sem_no_discovery_publish_or_consume` (full continuous enforcement, including the relay path
//! watcher, is M4). Dial accepts only ticket-carried `EndpointAddr`s (see
//! [`endpoint_addr_from_ticket`]).
//!
//! **Relay is disabled.** M2 is LAN-direct; the holepunch coordinator is M4 wiring
//! (`RelayMode::Disabled` is always set explicitly — never left to a default).
//!
//! **iroh 1.0.3 spike (DESIGN §12.7), re-confirmed against the downloaded crate source +
//! its own test suite (2026-07-23):** `Endpoint::builder` requires a preset; `presets::Minimal`
//! pulls in no discovery service at all (confirmed: it only sets the TLS crypto provider).
//! Version floor ≥1.0.2 (relay receive-lane fairness fix); pinned to 1.0.3 (empty-ALPN accept
//! fix). `EndpointAddr { id: EndpointId, addrs: BTreeSet<TransportAddr> }`,
//! `EndpointAddr::from_parts(id, addrs)`, `EndpointId = PublicKey` with `from_bytes(&[u8;32])` /
//! `as_bytes() -> &[u8;32]`, `Endpoint::addr() -> EndpointAddr` (sync, `.ip_addrs()` populated as
//! soon as a local interface is bound — no relay/"online" wait needed for LAN addresses) all
//! confirmed present as this module uses them.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use mascara_core::{Identity, Ticket};

use crate::error::NetError;

/// The one protocol ALPN this milestone speaks.
pub const XFER_ALPN: &[u8] = b"/mascara/xfer/1";

/// The shared builder discipline: discovery off by construction (`presets::Minimal`), relay
/// disabled (always explicit — never left to a default), our identity's transport secret as the
/// iroh secret key, and the one ALPN we serve.
fn base_builder(identity: &Identity) -> iroh::endpoint::Builder {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(&identity.transport_secret_bytes()))
        .alpns(vec![XFER_ALPN.to_vec()])
        .relay_mode(iroh::RelayMode::Disabled)
}

/// The fixed UDP port a *servable* endpoint always binds (IPv4, all interfaces). `send` and
/// `serve` are separate process invocations (spec §CLI) — an OS-assigned ephemeral port would
/// make `send`'s gathered addresses (baked into the ticket) stale the instant that short-lived
/// bind closes, since `serve`'s later bind would land on a *different* random port and the
/// ticket's `ip:port` candidates would never again be dialable. A fixed, well-known port (the
/// BitTorrent/syncthing pattern) keeps a ticket's addresses valid for as long as `serve` runs on
/// the same box (M2's documented LAN-direct limitation — the coordinator that makes this
/// survive a changed port/box is M4).
pub const DEFAULT_PORT: u16 = 41000;

/// Bind a *servable* production endpoint on [`DEFAULT_PORT`], all IPv4 interfaces — used by
/// `mascara send` (to gather the addresses baked into the ticket) and `mascara serve` (the
/// listener itself), so the two agree on a port even across separate process invocations. NEVER
/// call `.online()` on an endpoint built this way — `RelayMode::Disabled` means there is no relay
/// to report readiness through, and it would hang forever.
pub async fn build_endpoint(identity: &Identity) -> Result<iroh::Endpoint, NetError> {
    base_builder(identity)
        .clear_ip_transports()
        .bind_addr((std::net::Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))
        .map_err(|e| NetError::Endpoint(format!("invalid bind address: {e}")))?
        .bind()
        .await
        .map_err(|e| {
            NetError::Endpoint(format!(
                "could not bind the transfer endpoint on port {DEFAULT_PORT}: {e} \
                 (only one Mascara `send`/`serve` can use this port on a device at a time)"
            ))
        })
}

/// Bind a *dial-only* production endpoint on an OS-assigned ephemeral port — used by `mascara
/// recv`, which only ever makes outbound connections and is never dialed back into, so it needs
/// no stable port (and, unlike [`build_endpoint`], can run alongside a `serve`/`send` on the same
/// box without a port conflict).
pub async fn build_dialing_endpoint(identity: &Identity) -> Result<iroh::Endpoint, NetError> {
    base_builder(identity)
        .bind()
        .await
        .map_err(|e| NetError::Endpoint(format!("could not bind the transfer endpoint: {e}")))
}

/// Bind to loopback only (`127.0.0.1:0`) — for L1 tests and `mascara-it`'s two-endpoints-in-one-
/// process harness. Same discovery-off/relay-disabled discipline as [`build_endpoint`].
pub async fn build_loopback_endpoint(identity: &Identity) -> Result<iroh::Endpoint, NetError> {
    base_builder(identity)
        .clear_ip_transports()
        .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| NetError::Endpoint(format!("invalid loopback bind address: {e}")))?
        .bind()
        .await
        .map_err(|e| NetError::Endpoint(format!("could not bind the loopback transfer endpoint: {e}")))
}

/// This endpoint's own reachable direct addresses, as the ticket's network-agnostic
/// [`mascara_core::Endpoint`] (DESIGN §3): each `SocketAddr` stringified (`SocketAddr::to_string`
/// already brackets IPv6 — `[2001:db8::1]:41000` — matching [`endpoint_addr_from_ticket`]'s
/// `SocketAddr::from_str` on the dial side). `coordinator` stays `None` at M2 (no coordinator
/// wiring — M4). Briefly polls for iroh to finish gathering interface addresses, bounded so a
/// caller (`mascara send`) stays "non-blocking-simple".
pub async fn local_endpoint_addrs(ep: &iroh::Endpoint) -> mascara_core::Endpoint {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let addr = loop {
        let addr = ep.addr();
        if addr.ip_addrs().count() > 0 || tokio::time::Instant::now() >= deadline {
            break addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let addrs = addr
        .addrs
        .iter()
        .filter_map(|t| match t {
            iroh::TransportAddr::Ip(sa) => Some(sa.to_string()),
            _ => None,
        })
        .collect();
    mascara_core::Endpoint { addrs, coordinator: None }
}

/// Rebuild the sender's dialable `EndpointAddr` from an opened ticket (DESIGN §3): `endpoint_key`
/// is the transport public key the ticket was sealed to, `endpoint.addrs` are the direct
/// candidates gathered at issue time. A ticket with an unparseable key or address is a reasoned
/// refusal, never a panic — the paste channel is untrusted, and so, transitively, is everything
/// sealed inside it.
pub fn endpoint_addr_from_ticket(ticket: &Ticket) -> Result<iroh::EndpointAddr, NetError> {
    let id = iroh::PublicKey::from_bytes(&ticket.endpoint_key).map_err(|e| {
        NetError::Protocol(format!("ticket endpoint_key is not a valid transport key: {e}"))
    })?;
    let mut addrs: BTreeSet<iroh::TransportAddr> = BTreeSet::new();
    for s in &ticket.endpoint.addrs {
        let sa = SocketAddr::from_str(s).map_err(|e| {
            NetError::Protocol(format!("ticket carries an unparseable address '{s}': {e}"))
        })?;
        addrs.insert(iroh::TransportAddr::Ip(sa));
    }
    if addrs.is_empty() {
        return Err(NetError::Protocol("ticket carries no direct address candidates".into()));
    }
    Ok(iroh::EndpointAddr::from_parts(id, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mascara_core::{Endpoint as CoreEndpoint, FileRef, Nonce};

    fn sample_file_ref() -> FileRef {
        FileRef { name: "a".into(), size: 1, sha256: [0u8; 32], md5: [0u8; 16], mime: None }
    }

    #[test]
    fn endpoint_addr_from_ticket_round_trips_a_socket_addr() {
        let identity = Identity::mint();
        let card = identity.card();
        let ticket = Ticket::new_file(
            sample_file_ref(),
            CoreEndpoint { addrs: vec!["127.0.0.1:41000".into()], coordinator: None },
            card.transport_pk,
            None,
            None,
            Nonce::mint(),
        );
        let addr = endpoint_addr_from_ticket(&ticket).unwrap();
        assert_eq!(addr.id.as_bytes(), &card.transport_pk);
        assert_eq!(addr.ip_addrs().count(), 1);
    }

    #[test]
    fn unparseable_address_is_a_reasoned_error() {
        let identity = Identity::mint();
        let ticket = Ticket::new_file(
            sample_file_ref(),
            CoreEndpoint { addrs: vec!["not-an-address".into()], coordinator: None },
            identity.card().transport_pk,
            None,
            None,
            Nonce::mint(),
        );
        assert!(matches!(endpoint_addr_from_ticket(&ticket), Err(NetError::Protocol(_))));
    }

    #[test]
    fn no_addresses_is_a_reasoned_error() {
        let identity = Identity::mint();
        let ticket = Ticket::new_file(
            sample_file_ref(),
            CoreEndpoint::default(),
            identity.card().transport_pk,
            None,
            None,
            Nonce::mint(),
        );
        assert!(matches!(endpoint_addr_from_ticket(&ticket), Err(NetError::Protocol(_))));
    }

    /// Real (loopback) iroh: confirms the discovery-off / relay-disabled construction actually
    /// binds and reports a dialable loopback address — the seam every other real-iroh test here
    /// and in `mascara-it` depends on.
    #[tokio::test]
    async fn loopback_endpoint_binds_and_reports_an_addr() {
        let identity = Identity::mint();
        let ep = build_loopback_endpoint(&identity).await.unwrap();
        let addr = local_endpoint_addrs(&ep).await;
        assert!(!addr.addrs.is_empty(), "a bound loopback endpoint must report at least one addr");
        assert!(addr.addrs.iter().all(|a| a.starts_with("127.0.0.1:")), "got: {addr:?}");
        ep.close().await;
    }
}
