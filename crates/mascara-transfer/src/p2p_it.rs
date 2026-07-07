//! hb-p2p-it — headless P2P integration harness (Test Plan Layer 3 / Suite P).
//!
//! **Geo-manual, NOT in CI.** Drives the **real** v0.9 binding-gated file-transfer code in
//! `transfer.rs` (+ the sealed-presence resolution in `presence.rs`) between live endpoints over
//! real NAT-traversed QUIC. The security-critical trust logic (the H2/H17 gate, the address seal)
//! is L1-tested in `hb-core` so CI guards it; this harness proves the same gate end-to-end at the
//! geo gate. See TEST_PLAN.md §5.
//!
//! Two roles:
//!
//!   hb-p2p-it serve --data-dir <dir> --relay <url>... [--follow <npub>]
//!     Seeds shared collections + files, publishes a **sealed presence binding** to the relay(s),
//!     and runs the real binding-gated xfer accept loop. Prints its `hbk…` share code (the peer
//!     identity + account browse-key a probe needs to resolve the sealed address).
//!
//!   hb-p2p-it probe --peer <hbk…> --relay <url>... [--save-dir <dir>]
//!     Resolves the peer's node key + address from their **verified presence binding** (H2),
//!     presents an npub-signed binding token (H17), runs Suite P, and emits TAP 13.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hb_core::ShareCode;
use hb_net::RelayClient;
use nostr::prelude::ToBech32;

use crate::identity_state::AppIdentity;
use crate::store::{DataStore, ShareSettings, StoredIdentity};
use crate::transfer::{self, DownloadRegistry};

const SHARED_SLUG: &str = "p2p-it-films";
const PRIVATE_SLUG: &str = "p2p-it-private";
const SLOW_SLUG: &str = "p2p-it-slow";
const SHARED_FILE: &str = "sample.txt";
const SHARED_CONTENT: &[u8] = b"hoardbook p2p integration test payload\n";
const SLOW_FILE: &str = "big.bin";
const SLOW_FILE_SIZE: usize = 256 * 1024;
const SLOW_CAP_KBPS: u32 = 64;
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub(crate) async fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => match run_serve(&args[1..]).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => { eprintln!("[serve] error: {e:#}"); ExitCode::FAILURE }
        },
        Some("probe") => match run_probe(&args[1..]).await {
            Ok(code) => code,
            Err(e) => { eprintln!("[probe] error: {e:#}"); ExitCode::FAILURE }
        },
        // backup/restore: exercise the M5 portable-backup seam across *real* machines (the one
        // thing the offline dev env could not — restore on different hardware). Prints the npub on
        // each side so a caller can assert the identity survives the round-trip.
        Some("backup") => match run_backup(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => { eprintln!("[backup] error: {e:#}"); ExitCode::FAILURE }
        },
        Some("restore") => match run_restore(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => { eprintln!("[restore] error: {e:#}"); ExitCode::FAILURE }
        },
        _ => {
            eprintln!(
                "usage: hb-p2p-it <serve|probe|backup|restore> [options]\n\
                 \n\
                 serve   --data-dir <dir> --relay <url>... [--follow <npub>]\n\
                 probe   --peer <hbk…> --relay <url>... [--save-dir <dir>]\n\
                 backup  --data-dir <dir> --out <file> (--passphrase <pp> | --plaintext)\n\
                 restore --data-dir <empty-dir> --in <file> [--passphrase <pp>]"
            );
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// backup / restore — M5 portable-backup seam, exercised across real machines
// ---------------------------------------------------------------------------

fn run_backup(args: &[String]) -> Result<()> {
    let data_dir = PathBuf::from(
        flag_value(args, "--data-dir").ok_or_else(|| anyhow!("backup requires --data-dir <dir>"))?,
    );
    let out = PathBuf::from(
        flag_value(args, "--out").ok_or_else(|| anyhow!("backup requires --out <file>"))?,
    );
    let store = DataStore::new(data_dir);
    let app_id = load_or_create_identity(&store)?;
    let plaintext = args.iter().any(|a| a == "--plaintext");
    let mode = if plaintext {
        hb_core::BackupMode::Plaintext
    } else {
        hb_core::BackupMode::Passphrase(
            flag_value(args, "--passphrase")
                .ok_or_else(|| anyhow!("backup requires --passphrase <pp> (or --plaintext)"))?,
        )
    };
    let archive = crate::backup::backup_inner(&store, mode).map_err(|e| anyhow!("backup: {e}"))?;
    std::fs::write(&out, &archive).with_context(|| format!("write {}", out.display()))?;
    println!("backed_up_npub={}", app_id.npub());
    println!("archive={} bytes={} encrypted={}", out.display(), archive.len(), !plaintext);
    Ok(())
}

fn run_restore(args: &[String]) -> Result<()> {
    let data_dir = PathBuf::from(
        flag_value(args, "--data-dir")
            .ok_or_else(|| anyhow!("restore requires --data-dir <empty-dir>"))?,
    );
    let input = PathBuf::from(
        flag_value(args, "--in").ok_or_else(|| anyhow!("restore requires --in <file>"))?,
    );
    let archive = std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
    let store = DataStore::new(data_dir);
    crate::backup::restore_inner(&store, &archive, flag_value(args, "--passphrase"))
        .map_err(|e| anyhow!("restore: {e}"))?;
    // Load-only (NOT load_or_create): a restore that left no identity must error, not silently
    // mint a fresh npub that would print as a false "restored" success (chorus: Gemini + opencode).
    let stored = store
        .load_identity()?
        .ok_or_else(|| anyhow!("restore wrote no identity — the archive did not contain one"))?;
    let app_id = AppIdentity::from_stored(&stored).map_err(|e| anyhow!("load restored identity: {e}"))?;
    println!("restored_npub={}", app_id.npub());
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async fn build_endpoint(secret_bytes: &[u8; 32]) -> Result<iroh::Endpoint> {
    iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(iroh::SecretKey::from_bytes(secret_bytes))
        .alpns(vec![transfer::XFER_ALPN.to_vec()])
        .bind()
        .await
        .context("bind iroh endpoint")
}

fn load_or_create_identity(store: &DataStore) -> Result<AppIdentity> {
    if let Some(stored) = store.load_identity()? {
        return AppIdentity::from_stored(&stored).map_err(|e| anyhow!("load identity: {e}"));
    }
    let id = AppIdentity::generate();
    let stored: StoredIdentity = id.to_stored().map_err(|e| anyhow!("serialize identity: {e}"))?;
    store.save_identity(&stored)?;
    Ok(id)
}

fn collect_relays(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--relay" {
            if let Some(v) = args.get(i + 1) { out.push(v.trim_end_matches('/').to_string()); }
        }
        i += 1;
    }
    out
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

fn seed_data(store: &DataStore, root: &Path) -> Result<()> {
    std::fs::create_dir_all(root).context("create shared root")?;
    std::fs::write(root.join(SHARED_FILE), SHARED_CONTENT).context("write shared file")?;
    std::fs::write(root.join(SLOW_FILE), vec![0xA5u8; SLOW_FILE_SIZE]).context("write slow file")?;
    let root_str = root.to_string_lossy().to_string();

    store.save_share_settings(SHARED_SLUG, &ShareSettings {
        enabled: true, root_path: Some(root_str.clone()), allowed_paths: vec![],
        speed_cap_kbps: None, download_limit: None, require_follow: false,
    })?;
    store.save_share_settings(PRIVATE_SLUG, &ShareSettings {
        enabled: true, root_path: Some(root_str.clone()), allowed_paths: vec![],
        speed_cap_kbps: None, download_limit: None, require_follow: true,
    })?;
    store.save_share_settings(SLOW_SLUG, &ShareSettings {
        enabled: true, root_path: Some(root_str), allowed_paths: vec![],
        speed_cap_kbps: Some(SLOW_CAP_KBPS), download_limit: None, require_follow: false,
    })?;
    Ok(())
}

async fn run_serve(args: &[String]) -> Result<()> {
    let data_dir = PathBuf::from(flag_value(args, "--data-dir").unwrap_or("./hb-p2p-it-data"));
    let relays = collect_relays(args);
    if relays.is_empty() {
        bail!("serve requires at least one --relay (presence is published to the relays)");
    }

    let store = DataStore::new(data_dir.clone());
    let app_id = load_or_create_identity(&store)?;
    let root = data_dir.join("shared");
    seed_data(&store, &root)?;

    // Optionally record a follower (so the require_follow collection admits a known probe npub).
    if let Some(follow) = flag_value(args, "--follow") {
        use crate::store::CachedPeer;
        store.save_contact(&CachedPeer::pubkey_hash(follow), &CachedPeer {
            npub: follow.to_string(), browse_key_hex: None, petname: None,
            profile: None, collections: vec![], online: true,
            last_fetched: chrono::Utc::now(), local_tags: vec![],
        })?;
        eprintln!("[serve] following {follow} (admitted to require_follow collections)");
    }

    let secret = app_id.iroh_secret;
    let node_key = app_id.iroh_node_key();
    let endpoint = build_endpoint(&secret).await?;
    let registry = Arc::new(DownloadRegistry::new());

    // The binding-gated xfer accept loop (production handler).
    let server_ep = endpoint.clone();
    let store_srv = store.clone();
    tokio::spawn(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(64));
        while let Some(incoming) = server_ep.accept().await {
            let Ok(permit) = sem.clone().acquire_owned().await else { break };
            let store = store_srv.clone();
            let registry = registry.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(accepting) = incoming.accept() else { return };
                let Ok(conn) = accepting.await else { return };
                if conn.alpn() == transfer::XFER_ALPN {
                    if let Err(e) = transfer::handle_xfer_connection(conn, store, registry).await {
                        eprintln!("[serve] xfer session error: {e}");
                    }
                }
            });
        }
    });

    // Let iroh gather addresses, then publish a sealed presence binding on a loop.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let share_code = app_id.share_code().map_err(|e| anyhow!(e))?;
    println!("npub={}", app_id.npub());
    println!("share_code={share_code}");
    eprintln!("[serve] listening; sealed presence publishing to {} relay(s)", relays.len());

    loop {
        let addr_json = serde_json::to_string(&endpoint.addr()).context("serialize node addr")?;
        match RelayClient::connect(&app_id.identity, &relays, RELAY_TIMEOUT).await {
            Ok(client) => {
                if let Err(e) = crate::presence::publish_presence(
                    &client, &app_id.identity, &node_key, &addr_json, &app_id.browse_key,
                ).await {
                    eprintln!("[serve] presence publish error: {e}");
                }
                client.disconnect().await;
            }
            Err(e) => eprintln!("[serve] relay connect error: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

// ---------------------------------------------------------------------------
// probe — Suite P
// ---------------------------------------------------------------------------

async fn run_probe(args: &[String]) -> Result<ExitCode> {
    let peer_code = flag_value(args, "--peer")
        .ok_or_else(|| anyhow!("probe requires --peer <hbk… share code>"))?;
    let relays = collect_relays(args);
    if relays.is_empty() {
        bail!("probe requires at least one --relay (the peer's presence is read from the relays)");
    }
    let save_dir = PathBuf::from(
        flag_value(args, "--save-dir")
            .map(str::to_string)
            .unwrap_or_else(|| std::env::temp_dir().join("hb-p2p-it").to_string_lossy().to_string()),
    );
    std::fs::create_dir_all(&save_dir).context("create save dir")?;

    let share = ShareCode::parse(peer_code).map_err(|e| anyhow!("invalid --peer code: {e}"))?;
    let peer_npub = share.pubkey();
    let browse_key = share.browse_key().ok_or_else(|| anyhow!("--peer must be a full hbk code"))?;

    // Ephemeral probe identity + endpoint.
    let probe = AppIdentity::generate();
    let endpoint = build_endpoint(&probe.iroh_secret).await?;
    let probe_node_key = probe.iroh_node_key();

    // H2: resolve the peer's address from their verified presence binding (before any QUIC).
    let client = RelayClient::connect(&probe.identity, &relays, RELAY_TIMEOUT).await?;
    let presence = crate::presence::fetch_peer_presence(&client, &peer_npub, RELAY_TIMEOUT)
        .await?
        .ok_or_else(|| anyhow!("no presence for {} on the relays", peer_npub.to_bech32().unwrap_or_default()))?;
    client.disconnect().await;
    let peer_addr = transfer::resolve_peer_addr(&presence, &peer_npub, &browse_key)?;

    let token = || transfer::build_token_frame(&probe.identity, &probe_node_key);

    let mut tap = Tap::new();

    // P2 (H2 pure half) — a presence that doesn't vouch for a *different* npub yields no address.
    tap.check("P2: binding identity-pin refuses a non-vouching presence (before dial)",
        probe_binding_pin(&presence, &browse_key));

    // P1 — download the shared file (bytes + sha256 match).
    tap.check("P1: download shared file (bytes + sha256 match)",
        probe_download_ok(&endpoint, peer_addr.clone(), token()?, &save_dir).await);

    // P3 — require_follow collection denies a stranger with `restricted to followers`.
    tap.check("P3: require_follow rejects a stranger",
        probe_download_denied(&endpoint, peer_addr.clone(), token()?, PRIVATE_SLUG, SHARED_FILE,
            &save_dir, "restricted to followers").await);

    // P4 — invalid slug rejected (M7) over the wire.
    tap.check("P4: invalid slug rejected",
        probe_download_denied(&endpoint, peer_addr.clone(), token()?, "../escape", SHARED_FILE,
            &save_dir, "Invalid collection slug").await);

    // AB6 — path traversal rejected.
    tap.check("AB6: path traversal rejected",
        probe_download_denied(&endpoint, peer_addr.clone(), token()?, SHARED_SLUG, "../secret",
            &save_dir, "Invalid file path").await);

    // AB5 — integrity mismatch deletes the partial, never auto-opens.
    tap.check("AB5: sha256 mismatch deletes the partial",
        probe_integrity_mismatch(&endpoint, peer_addr.clone(), token()?, &save_dir).await);

    // P5 — cancel mid-download aborts and removes the partial.
    tap.check("P5: cancel mid-download removes the partial",
        probe_cancel(&endpoint, peer_addr.clone(), token()?, &save_dir).await);

    endpoint.close().await;
    Ok(tap.finish())
}

/// P2 (H2 pure half): a presence whose binding vouches for `peer` must NOT resolve when we expect a
/// different npub — refuse-before-dial. The QUIC refusal is exercised implicitly (no dial happens).
fn probe_binding_pin(presence: &nostr::Event, browse_key: &hb_core::BrowseKey) -> Result<()> {
    let impostor = hb_core::Identity::generate().public_key();
    match transfer::resolve_peer_addr(presence, &impostor, browse_key) {
        Ok(_) => bail!("resolved an address for an npub the binding does not vouch for"),
        Err(_) => Ok(()),
    }
}

async fn probe_download_ok(
    endpoint: &iroh::Endpoint,
    peer_addr: iroh::EndpointAddr,
    token: Vec<u8>,
    save_dir: &Path,
) -> Result<()> {
    let registry = Arc::new(DownloadRegistry::new());
    let save_path = save_dir.join("downloaded.txt");
    let expected = transfer::sha256_bytes(SHARED_CONTENT);
    let n = transfer::download_file_inner(
        endpoint, peer_addr, token, SHARED_SLUG, SHARED_FILE,
        save_path.to_str().context("save path not utf-8")?,
        Some(expected), registry.next_id(), registry.clone(), |_ev| {},
    ).await?;
    if n as usize != SHARED_CONTENT.len() {
        bail!("downloaded {n} bytes, expected {}", SHARED_CONTENT.len());
    }
    if std::fs::read(&save_path).context("re-read")? != SHARED_CONTENT {
        bail!("downloaded content mismatch");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn probe_download_denied(
    endpoint: &iroh::Endpoint,
    peer_addr: iroh::EndpointAddr,
    token: Vec<u8>,
    slug: &str,
    path: &str,
    save_dir: &Path,
    expect_msg: &str,
) -> Result<()> {
    let registry = Arc::new(DownloadRegistry::new());
    let save_path = save_dir.join("denied.bin");
    match transfer::download_file_inner(
        endpoint, peer_addr, token, slug, path,
        save_path.to_str().context("save path not utf-8")?,
        None, registry.next_id(), registry.clone(), |_ev| {},
    ).await {
        Ok(_) => bail!("expected denial ({expect_msg}) but the download succeeded"),
        Err(e) => {
            let s = e.to_string();
            if s.contains(expect_msg) { Ok(()) } else { bail!("expected {expect_msg:?}, got: {s}") }
        }
    }
}

async fn probe_integrity_mismatch(
    endpoint: &iroh::Endpoint,
    peer_addr: iroh::EndpointAddr,
    token: Vec<u8>,
    save_dir: &Path,
) -> Result<()> {
    let registry = Arc::new(DownloadRegistry::new());
    let save_path = save_dir.join("tampered.txt");
    let bogus = transfer::sha256_bytes(b"not the served content");
    match transfer::download_file_inner(
        endpoint, peer_addr, token, SHARED_SLUG, SHARED_FILE,
        save_path.to_str().context("save path not utf-8")?,
        Some(bogus), registry.next_id(), registry.clone(), |_ev| {},
    ).await {
        Ok(_) => bail!("integrity check did not fire on a sha256 mismatch"),
        Err(e) => {
            if !e.to_string().contains("Integrity check failed") {
                bail!("expected an integrity failure, got: {e}");
            }
            if save_path.exists() { bail!("partial file was not removed after integrity failure"); }
            Ok(())
        }
    }
}

async fn probe_cancel(
    endpoint: &iroh::Endpoint,
    peer_addr: iroh::EndpointAddr,
    token: Vec<u8>,
    save_dir: &Path,
) -> Result<()> {
    let registry = Arc::new(DownloadRegistry::new());
    let save_path = save_dir.join("cancelled.bin");
    let save_str = save_path.to_str().context("save path not utf-8")?.to_string();
    let download_id = registry.next_id();

    let ep = endpoint.clone();
    let reg = registry.clone();
    let task = tokio::spawn(async move {
        transfer::download_file_inner(
            &ep, peer_addr, token, SLOW_SLUG, SLOW_FILE, &save_str,
            None, download_id, reg, |_ev| {},
        ).await
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;
    if !registry.cancel(download_id).await {
        let _ = task.await;
        bail!("cancel token gone — download finished before the cancel fired");
    }
    match task.await.context("join download task")? {
        Ok(n) => bail!("download completed ({n} bytes) despite cancellation"),
        Err(e) => {
            if !e.to_string().to_lowercase().contains("cancel") {
                bail!("expected the cancellation error, got: {e}");
            }
            if save_path.exists() { bail!("partial file was not removed after cancel"); }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal TAP 13 writer (trailing plan)
// ---------------------------------------------------------------------------

struct Tap { n: usize, failed: usize }

impl Tap {
    fn new() -> Self {
        println!("TAP version 13");
        Self { n: 0, failed: 0 }
    }
    fn check(&mut self, name: &str, result: Result<()>) {
        self.n += 1;
        match result {
            Ok(()) => println!("ok {} - {name}", self.n),
            Err(e) => {
                self.failed += 1;
                println!("not ok {} - {name}\n  ---\n  detail: {e}\n  ...", self.n);
            }
        }
    }
    fn finish(self) -> ExitCode {
        println!("1..{}", self.n);
        eprintln!("\n{} tests: {} passed, {} failed", self.n, self.n - self.failed, self.failed);
        if self.failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
    }
}
