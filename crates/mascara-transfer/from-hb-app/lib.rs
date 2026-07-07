#![forbid(unsafe_code)]

mod backup;
mod commands;
mod conn;
mod error;
mod identity_state;
mod net;
mod p2p_it;
mod presence;
mod store;
mod transfer;
mod update_logic;

use std::sync::Arc;
use store::DataStore;
use tauri::{
    Emitter, Manager,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
};
use tauri_plugin_updater::UpdaterExt;
use tokio::sync::RwLock;

pub use identity_state::{AppIdentity, SharedIdentity};

/// Managed state types — Arc-wrapped so they can be cloned into background tasks.
pub type SharedEndpoint = Arc<RwLock<Option<iroh::Endpoint>>>;
pub type SharedDownloadRegistry = Arc<transfer::DownloadRegistry>;
/// Sender half of the presence-loop cancel channel. Send `true` to stop the task.
pub type SharedCancelPresence = Arc<tokio::sync::watch::Sender<bool>>;

// ---------------------------------------------------------------------------
// iroh endpoint lifecycle helper
// ---------------------------------------------------------------------------

/// Create (or replace) the iroh P2P endpoint from the bound iroh transport key, persist it in
/// `endpoint_state`, and spawn the accept loop. iroh now dispatches **only** `XFER_ALPN` (the
/// node-browse ALPN was retired in M4 — browsing is a relay read).
pub(crate) async fn start_iroh_endpoint(
    iroh_secret: &[u8; 32],
    store: DataStore,
    endpoint_state: SharedEndpoint,
    app: tauri::AppHandle,
    download_registry: SharedDownloadRegistry,
) -> anyhow::Result<()> {
    let _ = &app; // reserved for future per-connection notifications
    let secret_key = iroh::SecretKey::from_bytes(iroh_secret);

    let new_ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![transfer::XFER_ALPN.to_vec()])
        .bind()
        .await?;

    let mut guard = endpoint_state.write().await;

    // Gracefully close any previous endpoint (its accept loop will exit naturally).
    if let Some(old) = guard.take() {
        old.close().await;
    }

    let server_ep = new_ep.clone();
    tauri::async_runtime::spawn(run_accept_loop(server_ep, store, download_registry));

    *guard = Some(new_ep);
    Ok(())
}

const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Dispatch incoming iroh connections. Only `XFER_ALPN` is served — every other ALPN is dropped.
async fn run_accept_loop(
    endpoint: iroh::Endpoint,
    store: DataStore,
    download_registry: SharedDownloadRegistry,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                tracing::debug!("iroh endpoint closed — accept loop exiting");
                break;
            }
        };

        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => { tracing::warn!("connection semaphore closed"); break; }
        };

        let store_clone = store.clone();
        let registry_clone = download_registry.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let accepting = match incoming.accept() {
                Ok(a) => a,
                Err(e) => { tracing::debug!("iroh incoming reject: {e}"); return; }
            };
            let conn = match accepting.await {
                Ok(c) => c,
                Err(e) => { tracing::debug!("iroh handshake error: {e}"); return; }
            };

            let alpn = conn.alpn().to_vec();
            if alpn == transfer::XFER_ALPN {
                if let Err(e) = transfer::handle_xfer_connection(conn, store_clone, registry_clone).await {
                    tracing::warn!("xfer session error: {e}");
                }
            } else {
                tracing::debug!("unknown ALPN on incoming connection, dropping");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Setup helpers — each owns one concern from the setup closure
// ---------------------------------------------------------------------------

/// Create the app data directory with restrictive permissions (mode 0700 on Unix).
fn create_app_data_dir(path: &std::path::Path) {
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .expect("could not create app data dir");
    }
    #[cfg(target_os = "windows")]
    std::fs::create_dir_all(path).expect("could not create app data dir");
}

/// Build the system tray with "Open Hoardbook" and "Quit" items.
fn build_system_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let show_item = MenuItemBuilder::with_id("show", "Open Hoardbook").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    let tray_menu = MenuBuilder::new(app).items(&[&show_item, &quit_item]).build()?;
    TrayIconBuilder::with_id("hb_tray")
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&tray_menu)
        .tooltip("Hoardbook")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "quit" => app.exit(0),
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// If an identity is on disk, populate `identity` and spawn the iroh endpoint.
/// Non-fatal: a failed endpoint logs a warning and the user can retry by restarting.
fn restore_identity_and_start_endpoint(
    store: DataStore,
    identity: SharedIdentity,
    endpoint_state: SharedEndpoint,
    download_registry: SharedDownloadRegistry,
    app: tauri::AppHandle,
) {
    let stored = match store.load_identity() {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            tracing::error!("Failed to load identity on startup: {e:#}");
            return;
        }
    };
    let app_id = match AppIdentity::from_stored(&stored) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Stored identity is corrupted: {e:#}");
            return;
        }
    };
    let iroh_secret = app_id.iroh_secret;

    // Populate synchronously so the presence task has an identity at its first fire.
    *identity.blocking_write() = Some(app_id);

    tauri::async_runtime::spawn(async move {
        if let Err(e) =
            start_iroh_endpoint(&iroh_secret, store, endpoint_state, app, download_registry).await
        {
            tracing::warn!("iroh endpoint startup failed: {e}");
        }
    });
}

/// Spawn the long-running background tasks: the presence-publish loop + the update check.
fn spawn_background_tasks(
    identity: SharedIdentity,
    endpoint_state: SharedEndpoint,
    presence_cancel_rx: tokio::sync::watch::Receiver<bool>,
    store: DataStore,
    app: tauri::AppHandle,
) {
    tauri::async_runtime::spawn(presence::run_presence_loop(
        identity,
        endpoint_state,
        store,
        presence_cancel_rx,
    ));

    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        match app.updater_builder().build() {
            Ok(updater) => match updater.check().await {
                Ok(Some(update)) => {
                    tracing::info!("Update available: v{}", update.version);
                    let _ = app.emit("update-available", &update.version);
                }
                Ok(None) => tracing::debug!("App is up to date"),
                Err(e) => tracing::debug!("Background update check failed: {e}"),
            },
            Err(e) => tracing::debug!("Updater not configured: {e}"),
        }
    });
}

// ---------------------------------------------------------------------------
// Integration harness entry point
// ---------------------------------------------------------------------------

/// Entry point for the `hb-p2p-it` headless P2P integration harness binary.
pub async fn run_p2p_it() -> std::process::ExitCode {
    p2p_it::run().await
}

// ---------------------------------------------------------------------------
// App entry point
// ---------------------------------------------------------------------------

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("could not resolve app data dir");

            create_app_data_dir(&data_dir);

            let store = DataStore::new(data_dir);

            let identity: SharedIdentity = Arc::new(RwLock::new(None));
            let endpoint_state: SharedEndpoint = Arc::new(RwLock::new(None));
            let download_registry: SharedDownloadRegistry =
                Arc::new(transfer::DownloadRegistry::new());
            let staged_update: commands::update::SharedStagedUpdate = Arc::default();

            let (presence_cancel_tx, presence_cancel_rx) = tokio::sync::watch::channel(false);
            let presence_cancel: SharedCancelPresence = Arc::new(presence_cancel_tx);

            app.manage(store.clone());
            app.manage(Arc::clone(&identity));
            app.manage(Arc::clone(&endpoint_state));
            app.manage(Arc::clone(&download_registry));
            app.manage(Arc::clone(&presence_cancel));
            app.manage(Arc::clone(&staged_update));

            build_system_tray(app)?;

            let app_handle = app.handle().clone();

            restore_identity_and_start_endpoint(
                store.clone(),
                Arc::clone(&identity),
                Arc::clone(&endpoint_state),
                Arc::clone(&download_registry),
                app_handle.clone(),
            );

            spawn_background_tasks(
                Arc::clone(&identity),
                Arc::clone(&endpoint_state),
                presence_cancel_rx,
                store,
                app_handle,
            );

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing hides to tray; "Quit" from the tray calls app.exit(0) instead.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::identity::generate_keypair,
            commands::identity::import_nsec,
            commands::identity::get_identity,
            commands::identity::get_share_code,
            commands::identity::validate_share_code,
            commands::identity::get_node_addr,
            commands::identity::backup_data,
            commands::identity::peek_backup,
            commands::identity::restore_data,
            commands::identity::wipe_data,
            commands::profile::save_profile,
            commands::profile::get_profile,
            commands::profile::publish_profile,
            commands::profile::unpublish_profile,
            commands::profile::has_published_profile,
            commands::collection::scan_directory,
            commands::collection::get_collections,
            commands::collection::delete_collection,
            commands::collection::publish_collection,
            commands::collection::update_collection_meta,
            commands::collection::export_collection,
            commands::browse::paste_key,
            commands::browse::follow,
            commands::browse::get_contacts,
            commands::browse::unfollow_contact,
            commands::browse::refresh_contact,
            commands::browse::set_contact_tags,
            commands::settings::get_settings,
            commands::settings::save_settings,
            commands::settings::check_relay,
            commands::settings::acknowledge_privacy_notice,
            commands::chat::send_message,
            commands::chat::get_messages,
            commands::sharing::get_share_settings,
            commands::sharing::save_share_settings,
            commands::sharing::request_download,
            commands::sharing::cancel_download,
            commands::groups::groups_get,
            commands::groups::groups_create,
            commands::groups::groups_rename,
            commands::groups::groups_delete,
            commands::groups::groups_assign,
            commands::groups::groups_unassign,
            commands::groups::contact_update_groups,
            commands::watches::watches_get,
            commands::watches::watches_create,
            commands::watches::watches_delete,
            commands::watches::watches_evaluate,
            commands::update::check_update,
            commands::update::download_update,
            commands::update::apply_staged_update,
            commands::update::take_update_notice,
        ])
        .build(tauri::generate_context!())
        .expect("error while running Hoardbook")
        // Obsidian deferred-install: apply a staged update as the app quits (Auto mode), so the
        // running-exe lock never bites and the user saw no mid-session interruption.
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                commands::update::apply_staged_on_exit(app);
            }
        });
}
