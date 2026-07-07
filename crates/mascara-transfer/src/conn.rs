//! Shared iroh connection lifecycle helpers.

/// Hold a connection open (bounded) until the peer closes it, before the connection is
/// dropped. Dropping it immediately after writing the response can send a
/// CONNECTION_CLOSE ahead of the (small) response on fast links, which the peer sees as
/// a truncated read. Shared by the xfer connection handler and the harness.
pub(crate) async fn drain_connection(conn: &iroh::endpoint::Connection) {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
}

// ---------------------------------------------------------------------------
// Regression test — connection-close truncation race (HANDOVER 2026-06-11 §2)
//
// The xfer handler used to drop the iroh Connection immediately after writing a small
// response; on a fast link the CONNECTION_CLOSE frame can race ahead of the response and
// the peer sees a truncated read. The loopback repro was deterministic. This test runs the
// REAL binding-gated handler over real QUIC on loopback (relay + discovery disabled), so
// removing the drain turns it red. The tiny `restricted to followers` denial is the smallest
// response on the transfer path — the documented deterministic loss without the drain.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use hb_core::Identity;

    use crate::store::{DataStore, ShareSettings};
    use crate::transfer::{self, DownloadRegistry};

    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Bind a loopback-only endpoint: relays and address lookup disabled, so the test never
    /// touches the network beyond 127.0.0.1/::1.
    async fn bind_local_endpoint(secret: &[u8; 32], alpns: Vec<Vec<u8>>) -> iroh::Endpoint {
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(secret))
            .alpns(alpns)
            .bind()
            .await
            .expect("bind loopback endpoint")
    }

    /// The server's EndpointAddr rewritten to loopback IPs (bound sockets are wildcard addresses).
    fn loopback_addr(server: &iroh::Endpoint) -> iroh::EndpointAddr {
        let mut addrs: BTreeSet<iroh::TransportAddr> = BTreeSet::new();
        for sock in server.bound_sockets() {
            let ip: IpAddr = if sock.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            addrs.insert(iroh::TransportAddr::Ip(SocketAddr::new(ip, sock.port())));
        }
        iroh::EndpointAddr { id: server.id(), addrs }
    }

    #[tokio::test]
    async fn xfer_error_response_survives_connection_close() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let server_secret: [u8; 32] = rand::random();
            let dir = tempfile::tempdir().unwrap();
            let store = DataStore::new(dir.path().to_path_buf());
            store
                .save_share_settings("col", &ShareSettings {
                    enabled: true,
                    require_follow: true, // a stranger is denied → the tiny error response
                    root_path: Some(dir.path().to_str().unwrap().to_string()),
                    ..Default::default()
                })
                .unwrap();

            let server =
                bind_local_endpoint(&server_secret, vec![transfer::XFER_ALPN.to_vec()]).await;

            let store_srv = store.clone();
            let server_ep = server.clone();
            tokio::spawn(async move {
                while let Some(incoming) = server_ep.accept().await {
                    let Ok(accepting) = incoming.accept() else { continue };
                    let Ok(conn) = accepting.await else { continue };
                    let registry = Arc::new(DownloadRegistry::new());
                    // Full production handler — owns the bi-stream accept and the drain under test.
                    let _ = transfer::handle_xfer_connection(conn, store_srv.clone(), registry).await;
                }
            });

            let client_secret: [u8; 32] = rand::random();
            let client = bind_local_endpoint(&client_secret, vec![]).await;
            let client_node = *client.id().as_bytes();
            let requester = Identity::generate(); // a stranger (not a follower)

            for round in 0..3 {
                let registry = Arc::new(DownloadRegistry::new());
                let save = dir.path().join(format!("out-{round}.bin"));
                let token = transfer::build_token_frame(&requester, &client_node).unwrap();
                let err = transfer::download_file_inner(
                    &client,
                    loopback_addr(&server),
                    token,
                    "col",
                    "f.txt",
                    save.to_str().unwrap(),
                    None,
                    registry.next_id(),
                    registry.clone(),
                    |_ev| {},
                )
                .await
                .expect_err("stranger must be denied");
                let msg = err.to_string();
                assert!(
                    msg.contains("restricted to followers"),
                    "round {round}: the follower-gate denial must arrive intact, got: {msg}"
                );
            }

            client.close().await;
            server.close().await;
        })
        .await
        .expect("test timed out");
    }
}
