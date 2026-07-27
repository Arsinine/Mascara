//! Open ticket → consent gate → dial (DESIGN §1/§5). The public transfer function requires a
//! [`ConsentAck`] by value — MAS-INV-4 structural: there is no path from "ticket opened" to
//! "bytes moving" that skips it (`sem_no_bytes_before_consent`).
//!
//! **M3 stage 3 — folder flow (DESIGN §5 two-stage consent).** [`fetch_manifest`] is stage 1
//! (consent covers the dial + manifest fetch); [`pull_folder`] is stage 2 (the explicit start
//! action after the manifest verifies and the receiver sees the file list + total size). The two
//! are separate entry points so the CLI/GUI can interpose the second confirm between them —
//! folding both confirms into `--yes` for scripts is stage 4's CLI wiring.

use std::path::{Path, PathBuf};
use std::time::Duration;

use iroh::endpoint::{ApplicationClose, Connection, ConnectionError};
use mascara_core::{Manifest, ManifestEntry, Ticket};

use crate::consent::ConsentAck;
use crate::endpoint::{endpoint_addr_from_ticket, XFER_ALPN};
use crate::error::NetError;

/// Connect to the ticket's sender, pinning the carried card's transport key (DESIGN §5/§6): with
/// discovery off both directions and dialing by `EndpointAddr`, iroh guarantees the connected
/// remote IS the dialed key; this asserts it anyway (defense in depth — a corrupted/foreign ticket
/// must never silently connect to the wrong peer).
async fn dial(ep: &iroh::Endpoint, ticket: &Ticket) -> Result<Connection, NetError> {
    let addr = endpoint_addr_from_ticket(ticket)?;
    let pinned_transport_pk = ticket
        .sender_card()
        .map_err(|e| NetError::Protocol(format!("ticket carries an invalid sender card: {e}")))?
        .transport_pk;
    let conn = ep
        .connect(addr, XFER_ALPN)
        .await
        .map_err(|e| NetError::Connection(format!("could not connect to the sender: {e}")))?;
    if conn.remote_id().as_bytes() != &pinned_transport_pk {
        conn.close(1u32.into(), b"endpoint mismatch");
        return Err(NetError::Connection(
            "connected peer does not match the ticket's sender card transport key".into(),
        ));
    }
    Ok(conn)
}

/// Translate a stream I/O failure into the DESIGN §4 cancel/connection-lost distinction (the one
/// iroh-aware translation point — the engine is generic over `AsyncRead+AsyncWrite`).
async fn classify_io_failure(conn: &Connection, err: NetError) -> NetError {
    match err {
        NetError::Io(_) => match tokio::time::timeout(Duration::from_secs(2), conn.closed()).await {
            Ok(ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. }))
                if error_code == 1u32.into() =>
            {
                NetError::Cancelled
            }
            _ => NetError::ConnectionLost(
                "direct connection lost — transfer stopped, nothing was sent via relay".into(),
            ),
        },
        other => other,
    }
}

/// Dial the ticket's sender and pull its one file into `dest_dir` (DESIGN §4/§6). Requires a
/// [`ConsentAck`] — see the `consent` module docs for why the type is the whole mechanism.
///
/// **File-only.** A `Payload::Folder` ticket is refused with a reasoned error — folder transfer
/// goes through [`fetch_manifest`] + [`pull_folder`] (the two-stage-consent path, DESIGN §5).
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
    let file_ref = ticket.file_ref().ok_or_else(|| {
        NetError::Protocol(
            "this ticket is for a folder; use the folder flow (fetch_manifest + pull_folder)".into(),
        )
    })?;

    let conn = dial(ep, ticket).await?;

    let stream_result = async {
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| NetError::Connection(format!("could not open a stream: {e}")))?;
        crate::engine::pull_file(send, recv, ticket.nonce, file_ref, 0, dest_dir, on_progress).await
    }
    .await;

    let result = match stream_result {
        Err(e) => {
            let e = classify_io_failure(&conn, e).await;
            // The engine kept the `.part` for a generic stream break (it cannot see close codes);
            // now that the break is resolved to a peer cancel, honor DESIGN §4 delete-on-cancel
            // (`sem_partials_deleted_on_cancel`). A real connection loss still keeps it (resume).
            if matches!(e, NetError::Cancelled) {
                crate::engine::remove_partial_on_cancel(dest_dir, &file_ref.name);
            }
            Err(e)
        }
        other => other,
    };
    conn.close(0u32.into(), b"");
    result
}

/// **Stage-1 consent entry point (DESIGN §5).** Dial the ticket's sender and fetch + verify the
/// folder manifest. The [`ConsentAck`] covers the dial + the manifest fetch ("direct connection —
/// the sharer sees your IP; folder contents/size not yet known"). The manifest is fully buffered,
/// its bytes hashed against `folder_ref.root_hash` BEFORE any entry is returned
/// (`sem_folderref_manifest_verified_before_use`), and cached at
/// `<dest_root>/manifests/<nonce-hex>.postcard` for resume. The caller runs the stage-2 confirm
/// after this returns (showing the file list + total size), then calls [`pull_folder`].
pub async fn fetch_manifest(
    ep: &iroh::Endpoint,
    ticket: &Ticket,
    _ack: ConsentAck,
    dest_root: &Path,
) -> Result<Manifest, NetError> {
    let folder_ref = ticket.folder_ref().ok_or_else(|| {
        NetError::Protocol("this ticket is for a single file; use pull(), not fetch_manifest()".into())
    })?;
    let conn = dial(ep, ticket).await?;
    let stream_result = async {
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| NetError::Connection(format!("could not open a stream: {e}")))?;
        crate::engine::fetch_manifest(send, recv, ticket.nonce, folder_ref, dest_root).await
    }
    .await;
    let result = match stream_result {
        Err(e) => Err(classify_io_failure(&conn, e).await),
        other => other,
    };
    conn.close(0u32.into(), b"");
    result
}

/// **Stage-2 consent entry point (DESIGN §5).** Pull every entry in `manifest` sequentially into
/// `dest_root`, one bi-stream per entry (each hash-verified via [`crate::engine::pull_file`]).
/// `on_file_progress(rel_path, done, total)` fires per chunk. The manifest must be the one
/// returned by [`fetch_manifest`] (its `root_hash` was already verified against the ticket's
/// `folder_ref`); a stale cached manifest vs a fresh fetch fails closed at fetch time (FQ3).
///
/// Folders resume per file: a partial `<leaf>.part` from an interrupted attempt is detected and
/// resumed by [`crate::engine::pull_file`] on each entry's pull.
///
/// `on_entry_done(entry, landed_path)` fires as each entry completes and verifies, before the next
/// begins — a partway failure still reports everything that finished (codex #8).
pub async fn pull_folder<P, D>(
    ep: &iroh::Endpoint,
    ticket: &Ticket,
    _ack: ConsentAck,
    manifest: &Manifest,
    dest_root: &Path,
    on_file_progress: P,
    on_entry_done: D,
) -> Result<Vec<PathBuf>, NetError>
where
    P: FnMut(&str, u64, u64),
    D: FnMut(&ManifestEntry, &Path),
{
    // A file ticket cannot be pulled as a folder.
    if ticket.folder_ref().is_none() {
        return Err(NetError::Protocol(
            "this ticket is for a single file; use pull(), not pull_folder()".into(),
        ));
    }
    let conn = dial(ep, ticket).await?;
    // One bi-stream per entry; the engine's `open_stream` callback owns `conn.open_bi()`.
    let conn_ref = &conn;
    let nonce = ticket.nonce;
    let open_stream = |_entry: &ManifestEntry| async move {
        let (send, recv) = conn_ref
            .open_bi()
            .await
            .map_err(|e| NetError::Connection(format!("could not open a stream: {e}")))?;
        Ok::<_, NetError>((
            Box::new(send) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
            Box::new(recv) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        ))
    };
    let result = crate::engine::pull_folder(
        manifest,
        nonce,
        dest_root,
        open_stream,
        on_file_progress,
        on_entry_done,
    )
    .await;
    let result = match result {
        Err(e) => {
            let e = classify_io_failure(&conn, e).await;
            // Same delete-on-cancel discipline as [`pull`], folder form: a resolved peer cancel
            // discards every in-flight `.part` beneath the destination; a real connection loss
            // keeps them (folders resume per file).
            if matches!(e, NetError::Cancelled) {
                crate::engine::remove_entry_partials_on_cancel(dest_root, manifest);
            }
            Err(e)
        }
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

    /// A ticket whose sender card's transport key does not match any real endpoint must fail to
    /// connect (or, extremely defensively, fail the remote-id pin) — never silently succeed against
    /// the wrong peer.
    #[tokio::test]
    async fn dial_refuses_when_ticket_points_at_no_listener() {
        let dialer_identity = Identity::mint();
        let dialer_ep = build_loopback_endpoint(&dialer_identity).await.unwrap();

        // A real (valid, bound) card whose transport key nothing listens on — the carried card must
        // parse, but the dial must fail to reach a peer at that key.
        let unlistened_card = Identity::mint().card();
        let ticket = Ticket::new_file(
            FileRef { name: "a".into(), size: 1, sha256: [0u8; 32], md5: [0u8; 16], mime: None },
            CoreEndpoint { addrs: vec!["127.0.0.1:1".into()], coordinator: None }, // nothing listens here
            unlistened_card.payload_bytes(),
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
            Ok(r) => assert!(r.is_err(), "a dead/foreign sender card transport key must never succeed"),
            Err(_timeout) => {}
        }
        dialer_ep.close().await;
    }
}
