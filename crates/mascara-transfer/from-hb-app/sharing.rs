//! File-sharing settings + the H2 client download path.
//!
//! `request_download` performs **H2** before any QUIC: it fetches the peer's presence binding from
//! the relays, resolves the dialable node key + address *from the verified binding*
//! (`transfer::resolve_peer_addr`, which calls `hb-core::verify_binding`), and mints the
//! downloader's own `npub`-signed binding token. A lying relay can't redirect the download — the
//! address only resolves if the target npub vouched for that node key.

use nostr::prelude::ToBech32;
use tauri::{AppHandle, State};

use crate::{
    identity_state::SharedIdentity,
    net,
    store::{CachedPeer, DataStore, ShareSettings},
    SharedDownloadRegistry, SharedEndpoint,
    error::{CmdResult, cmd_err},
};

#[tauri::command]
pub async fn get_share_settings(
    slug: String,
    store: State<'_, DataStore>,
) -> CmdResult<ShareSettings> {
    Ok(store.load_share_settings(&slug).map_err(cmd_err)?.unwrap_or_default())
}

#[tauri::command]
pub async fn save_share_settings(
    slug: String,
    settings: ShareSettings,
    store: State<'_, DataStore>,
) -> CmdResult<()> {
    store.save_share_settings(&slug, &settings).map_err(cmd_err)
}

/// Resolve the browse-key for a peer: from the pasted full share code, else from the saved contact.
fn peer_browse_key(
    share_code: &hb_core::ShareCode,
    peer_npub: &str,
    store: &DataStore,
) -> Result<hb_core::BrowseKey, String> {
    if let Some(bk) = share_code.browse_key() {
        return Ok(bk);
    }
    let contact = store
        .load_contact(&CachedPeer::pubkey_hash(peer_npub))
        .map_err(cmd_err)?
        .ok_or("You need this peer's full share code (hbk…) to reach them")?;
    let hexk = contact
        .browse_key_hex
        .ok_or("You need this peer's full share code (hbk…) to reach them")?;
    let bytes: [u8; 32] = hex::decode(&hexk)
        .map_err(cmd_err)?
        .try_into()
        .map_err(|_| "stored browse-key is not 32 bytes".to_string())?;
    Ok(bytes)
}

/// Download a file from a peer's shared collection over iroh, gated by the v0.9 binding (H2/H17).
/// `peer` is the peer's npub or full `hbk` share code. Returns the download ID for progress/cancel.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn request_download(
    peer: String,
    slug: String,
    path: String,
    save_path: String,
    expected_sha256: Option<String>,
    app: AppHandle,
    identity: State<'_, SharedIdentity>,
    endpoint: State<'_, SharedEndpoint>,
    registry: State<'_, SharedDownloadRegistry>,
    store: State<'_, DataStore>,
) -> CmdResult<u64> {
    // Our identity + iroh node key (for the binding token we present).
    let (id_clone, my_node_key) = {
        let guard = identity.read().await;
        let id = guard.as_ref().ok_or("No identity loaded. Generate a keypair first.")?;
        (id.identity.clone(), id.iroh_node_key())
    };

    // The peer's npub + browse-key (from the share code, or the saved contact).
    let share_code = hb_core::ShareCode::parse(&peer)
        .map_err(|e| format!("Invalid peer share code: {e}"))?;
    let peer_npub = share_code.pubkey();
    let peer_npub_str = peer_npub.to_bech32().map_err(cmd_err)?;
    let browse_key = peer_browse_key(&share_code, &peer_npub_str, &store)?;

    // Our bound endpoint.
    let ep = {
        let guard = endpoint.read().await;
        guard.as_ref()
            .ok_or("P2P transport not initialised. Generate or import a keypair first.")?
            .clone()
    };

    // H2: fetch + verify the peer's presence binding, resolve the address *before* dialing.
    let client = net::connect(&id_clone, &store).await.map_err(cmd_err)?;
    let presence = crate::presence::fetch_peer_presence(&client, &peer_npub, net::RELAY_TIMEOUT)
        .await
        .map_err(cmd_err)?;
    client.disconnect().await;
    let presence = presence.ok_or("Peer is offline (no current presence on the relays).")?;
    let peer_addr = crate::transfer::resolve_peer_addr(&presence, &peer_npub, &browse_key)
        .map_err(cmd_err)?;

    // Our binding token (the first XFER frame).
    let token_bytes = crate::transfer::build_token_frame(&id_clone, &my_node_key).map_err(cmd_err)?;

    let id = registry.next_id();
    let reg = (*registry).clone();

    tauri::async_runtime::spawn(async move {
        if let Err(e) = crate::transfer::download_file(
            &ep, peer_addr, token_bytes, &slug, &path, &save_path, expected_sha256, id, reg, app,
        ).await {
            tracing::warn!("download {id} failed: {e}");
        }
    });

    Ok(id)
}

/// Cancel an active download by ID.
#[tauri::command]
pub async fn cancel_download(
    download_id: u64,
    registry: State<'_, SharedDownloadRegistry>,
) -> CmdResult<bool> {
    Ok(registry.cancel(download_id).await)
}
