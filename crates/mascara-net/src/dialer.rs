//! Open ticket → consent gate → dial (DESIGN §1/§5). The public transfer function requires a
//! [`ConsentAck`] by value — MAS-INV-4 structural: there is no path from "ticket opened" to
//! "bytes moving" that skips it (`sem_no_bytes_before_consent`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use iroh::endpoint::{ApplicationClose, Connection, ConnectionError};
use mascara_core::Ticket;

use crate::consent::ConsentAck;
use crate::endpoint::{endpoint_addr_from_ticket, XFER_ALPN};
use crate::error::NetError;

/// Connect to the ticket's sender, pinning `endpoint_key` (DESIGN §5/§6): with discovery off
/// both directions and dialing by `EndpointAddr`, iroh guarantees the connected remote IS the
/// dialed key; this asserts it anyway (defense in depth — a corrupted/foreign ticket must never
/// silently connect to the wrong peer).
async fn dial(ep: &iroh::Endpoint, ticket: &Ticket) -> Result<Connection, NetError> {
    let addr = endpoint_addr_from_ticket(ticket)?;
    let conn = ep
        .connect(addr, XFER_ALPN)
        .await
        .map_err(|e| NetError::Connection(format!("could not connect to the sender: {e}")))?;
    if conn.remote_id().as_bytes() != &ticket.endpoint_key {
        conn.close(1u32.into(), b"endpoint mismatch");
        return Err(NetError::Connection(
            "connected peer does not match the ticket's endpoint_key".into(),
        ));
    }
    Ok(conn)
}

/// Dial the ticket's sender and pull its one file into `dest_dir` (DESIGN §4/§6). Requires a
/// [`ConsentAck`] — see the `consent` module docs for why the type is the whole mechanism.
///
/// Distinguishes a peer-initiated cancel (QUIC close, application error code 1) from an ordinary
/// connection loss: [`crate::engine::pull_file`] is generic over `AsyncRead+AsyncWrite` (so it
/// runs unchanged over `tokio::io::duplex` in tests) and so cannot see QUIC close codes — this is
/// the one iroh-aware translation point (DESIGN §4/§6).
pub async fn pull(
    ep: &iroh::Endpoint,
    ticket: &Ticket,
    _ack: ConsentAck,
    dest_dir: &Path,
    on_progress: impl FnMut(u64, u64),
) -> Result<PathBuf, NetError> {
    let conn = dial(ep, ticket).await?;

    let stream_result = async {
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| NetError::Connection(format!("could not open a stream: {e}")))?;
        crate::engine::pull_file(send, recv, ticket.nonce, &ticket.file_ref, 0, dest_dir, on_progress).await
    }
    .await;

    let result = match stream_result {
        Err(NetError::Io(_)) => match tokio::time::timeout(Duration::from_secs(2), conn.closed()).await {
            Ok(ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. }))
                if error_code == 1u32.into() =>
            {
                Err(NetError::Cancelled)
            }
            _ => Err(NetError::ConnectionLost(
                "direct connection lost — transfer stopped, nothing was sent via relay".into(),
            )),
        },
        other => other,
    };
    conn.close(0u32.into(), b"");
    result
}

/// Cancel an in-progress pull from the receiving side: QUIC close with application error code 1
/// (DESIGN §4) — the sender/engine sees this as a network error and the peer sees it as
/// `NetError::Cancelled` via [`pull`]'s translation. Exposed for a future interactive cancel
/// (M3+); M2's CLI does not wire an interactive trigger to it.
pub fn cancel(conn: &Connection) {
    conn.close(1u32.into(), b"cancelled");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::build_loopback_endpoint;
    use mascara_core::{Endpoint as CoreEndpoint, FileRef, Identity, Nonce};

    /// A ticket whose `endpoint_key` does not match any real endpoint must fail to connect
    /// (or, extremely defensively, fail the remote-id pin) — never silently succeed against the
    /// wrong peer.
    #[tokio::test]
    async fn dial_refuses_when_ticket_points_at_no_listener() {
        let dialer_identity = Identity::mint();
        let dialer_ep = build_loopback_endpoint(&dialer_identity).await.unwrap();

        let ticket = Ticket::new_file(
            FileRef { name: "a".into(), size: 1, sha256: [0u8; 32], md5: [0u8; 16], mime: None },
            CoreEndpoint { addrs: vec!["127.0.0.1:1".into()], coordinator: None }, // nothing listens here
            [42u8; 32], // not a real endpoint id
            None,
            None,
            Nonce::mint(),
        );

        let dest = tempfile::tempdir().unwrap();
        let ack = crate::consent::acknowledge_ip_exposure();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pull(&dialer_ep, &ticket, ack, dest.path(), |_, _| {}),
        )
        .await;
        // Either it timed out waiting on a dead address, or it returned a reasoned connection
        // error — either way, never a successful pull.
        match result {
            Ok(r) => assert!(r.is_err(), "a dead/foreign endpoint_key must never succeed"),
            Err(_timeout) => {}
        }
        dialer_ep.close().await;
    }
}
