//! `mascara` — the Phase-1 CLI, a thin front-end over `mascara-core`/`mascara-net` (DESIGN.md §8).
//! M3 surface: `card`, `send` (file + folder), `tickets`, `recv` (file + two-stage folder),
//! `serve`, `history` — transfers gated by the IP-exposure consent (`mascara-net::consent`,
//! MAS-INV-4), folder pulls by the second explicit start (DESIGN §5).
//!
//! MAS-INV-1: nothing here reaches a Hoardbook `npub`; the identity is Mascara's own.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use mascara_core::registry::IssuedRecord;
use mascara_core::{
    check_content, history, keystore, Card, ContentPolicy, ContentVerdict, FileStore, HistoryLog,
    Manifest, ManifestEntry, Nonce, Registry, ShareDescriptor, Ticket, TransferId, TransferState,
};

#[derive(Parser)]
#[command(
    name = "mascara",
    version,
    about = "Mascara — the courier: move a file you already agreed to move, behind its own identity"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print your reusable contact card — hand it out once, out-of-band, so a sender can seal a
    /// ticket to you. This is NOT your Hoardbook identity.
    Card,
    /// Issue a sealed file ticket for a recipient's card, and record its nonce so you can revoke it.
    Send {
        /// The share descriptor (from Hoardbook) for the file to offer, as a JSON file; Mascara no
        /// longer hashes files — the content commitment is carried, not computed (MR-13/MR-22).
        /// (Folders are M3.)
        descriptor: PathBuf,
        /// The recipient's contact card string (`mascara1…`).
        #[arg(long)]
        to: String,
        /// The actual file (or folder root, for a folder descriptor) on THIS device to serve
        /// for this ticket. Kept local-only — never
        /// sealed into the ticket, never sent (`mascara-net::listener::OfferStore`); the
        /// descriptor's `name`/`size`/hashes are the DECLARED facts Hoardbook carries. See the M2
        /// HANDOVER note: the spec's M1 CLI surface predates `serve` and had no path arg because
        /// no listener yet existed to read one.
        #[arg(long)]
        file: PathBuf,
    },
    /// List the tickets you have issued, or revoke one by id.
    Tickets {
        /// Revoke the ticket whose id (nonce hex, or a unique prefix) is given.
        #[arg(long)]
        revoke: Option<String>,
    },
    /// Open a pasted ticket string: prints the IP-exposure notice, prompts for consent (`--yes`
    /// still prints the notice — MAS-INV-4), then downloads the file into the current directory.
    Recv {
        /// The sealed ticket string (`mascara-ticket-v1:…`).
        ticket: String,
        /// Skip the interactive y/N prompt. The notice is still printed (MAS-INV-4) — this only
        /// skips asking, never the disclosure.
        #[arg(long)]
        yes: bool,
    },
    /// Run the transfer listener in the foreground until Ctrl-C (the tray uses the same listener
    /// at M5 — DESIGN §8).
    Serve,
    /// Show your local transfer history (what you hold — never shared, D9), or purge it.
    History {
        /// Delete every history record (`sem_history_local_only`: this is YOUR data to discard).
        #[arg(long)]
        purge: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let home = keystore::default_home()
        .context("could not determine the Mascara home directory (set $MASCARA_HOME)")?;
    match cli.command {
        Command::Card => cmd_card(&home),
        Command::Send { descriptor, to, file } => cmd_send(&home, &descriptor, &to, &file).await,
        Command::Tickets { revoke } => cmd_tickets(&home, revoke.as_deref()),
        Command::Recv { ticket, yes } => cmd_recv(&home, &ticket, yes).await,
        Command::Serve => cmd_serve(&home).await,
        Command::History { purge } => cmd_history(&home, purge),
    }
}

fn cmd_card(home: &Path) -> Result<()> {
    let (id, created) = keystore::init_if_missing(home).context("loading/creating your identity")?;
    if created {
        eprintln!("Minted a new Mascara identity at {} (this is NOT your Hoardbook identity).", home.display());
    }
    // The card string on stdout, clean for piping.
    println!("{}", id.card());
    Ok(())
}

async fn cmd_send(home: &Path, descriptor_path: &Path, to: &str, file: &Path) -> Result<()> {
    let recipient = Card::parse(to).context("the --to value is not a valid contact card")?;
    // Mascara no longer hashes files — the content commitment is carried in Hoardbook's share
    // descriptor (MR-13/MR-22). Load the facts; do not compute them.
    let descriptor = ShareDescriptor::from_json_file(descriptor_path)
        .with_context(|| format!("reading the share descriptor {}", descriptor_path.display()))?;
    let (id, _created) = keystore::init_if_missing(home).context("loading/creating your identity")?;

    // M2: bind the local endpoint long enough to gather real direct address candidates for the
    // ticket (DESIGN §3). `serve` re-binds and re-gathers its own addresses at serve time; for
    // M2's LAN-direct scope the sender and the listener must be the same box for the addresses to
    // still be valid at dial time (documented M2 limitation — coordinator-assisted reachability
    // that survives moving boxes is M4).
    let ep = mascara_net::endpoint::build_endpoint(&id)
        .await
        .context("binding the local transfer endpoint to gather address candidates")?;
    let endpoint = mascara_net::endpoint::local_endpoint_addrs(&ep).await;
    ep.close().await;

    let nonce = Nonce::mint();
    let registry = Registry::new(FileStore::at(home));
    let offers = mascara_net::listener::OfferStore::at(home);

    let (sealed, summary) = match descriptor {
        ShareDescriptor::File(file_descriptor) => {
            let name = file_descriptor.name.clone();
            let size = file_descriptor.size;
            let ticket =
                file_descriptor.into_file_ticket(endpoint, id.card().payload_bytes(), None, nonce);
            let sealed =
                ticket.seal(&recipient).context("sealing the ticket to the recipient's card")?;

            // Record the nonce BEFORE emitting the ticket, so nothing we hand out is
            // unrecorded/unrevokable. The stored recipient_transport_pk is the *recipient's*
            // transport pk — a disposable endpoint the M2 listener needs for anti-replay,
            // dropped on revoke/expire (MR-8).
            registry
                .issue(IssuedRecord::new(nonce, Some(name.clone()), Utc::now(), None, recipient.transport_pk))
                .context("recording the issued ticket")?;
            // Local-only bookkeeping: where do the bytes actually live for this nonce (never
            // sealed, never sent — see the M2 HANDOVER deviation note on `--file`). `serve`
            // reads this at request time.
            offers
                .record_file(
                    nonce,
                    file.to_path_buf(),
                    ticket.file_ref().expect("a file ticket carries a file_ref").clone(),
                    ticket.grant,
                )
                .context("recording the local file source for this ticket")?;
            (sealed, format!("'{name}' ({size} bytes)"))
        }
        ShareDescriptor::Folder(folder_descriptor) => {
            // M3: a folder descriptor mints a folder ticket. The manifest bytes are the
            // Hoardbook-precomputed commitment substrate (MR-13) — verified against the
            // descriptor's own root_hash at mint, stored for `serve` to stream byte-identical.
            let name = folder_descriptor.name.clone();
            let entry_count = folder_descriptor.entries.len();
            let total = checked_total(folder_descriptor.entries.iter().map(|e| e.size))
                .context("this folder descriptor's declared sizes are not a sane total")?;
            let (ticket, manifest_bytes) = folder_descriptor
                .into_folder_ticket(endpoint, id.card().payload_bytes(), None, nonce)
                .context("minting the folder ticket from the descriptor")?;
            // MR-12: a large manifest is a smell that this share wants to be a Buddy Backup
            // (Phase 2), not a one-shot folder ticket. Soft-warn only — the send proceeds.
            if manifest_bytes.len() > mascara_core::MANIFEST_SOFT_WARN_BYTES {
                eprintln!(
                    "note: this folder's manifest is {} bytes (over the {} soft cap) — a share \
                     this large fits Buddy Backup (Phase 2) better than a one-shot folder ticket.",
                    manifest_bytes.len(),
                    mascara_core::MANIFEST_SOFT_WARN_BYTES
                );
            }
            let sealed =
                ticket.seal(&recipient).context("sealing the ticket to the recipient's card")?;
            registry
                .issue(IssuedRecord::new(nonce, Some(name.clone()), Utc::now(), None, recipient.transport_pk))
                .context("recording the issued ticket")?;
            offers
                .record_folder(
                    nonce,
                    file.to_path_buf(),
                    ticket.folder_ref().expect("a folder ticket carries a folder_ref").clone(),
                    manifest_bytes,
                    ticket.grant,
                )
                .context("recording the local folder source for this ticket")?;
            (sealed, format!("folder '{name}' ({entry_count} files, {total} bytes)"))
        }
    };

    // Paste-only: the sealed ticket string goes to stdout. The `.mascara` file carrier is dropped
    // (MR-9) — a saved ticket file re-introduces origin (MR-7/8) and an auto-launch surface.
    println!("{sealed}");
    eprintln!(
        "Issued ticket {} for {summary}. Revoke with: mascara tickets --revoke {}",
        &nonce.to_hex()[..8],
        &nonce.to_hex()[..8]
    );
    eprintln!("Run `mascara serve` on this device to honor it (M2: sender and listener must be the same box).");
    Ok(())
}

fn cmd_tickets(home: &Path, revoke: Option<&str>) -> Result<()> {
    let registry = Registry::new(FileStore::at(home));
    if let Some(id) = revoke {
        let nonce = registry.revoke_by_prefix(id).context("revoking the ticket")?;
        eprintln!("Revoked ticket {} — the listener will refuse its nonce.", &nonce.to_hex()[..8]);
        return Ok(());
    }

    let tickets = registry.list().context("reading your issued tickets")?;
    if tickets.is_empty() {
        println!("No tickets issued yet.");
        return Ok(());
    }
    let now = Utc::now();
    println!("{:<10}  {:<8}  {:<20}  NAME", "ID", "STATUS", "ISSUED");
    for r in tickets {
        let status = if r.revoked {
            "revoked"
        } else if r.expires_at.is_some_and(|e| now >= e) {
            "expired"
        } else {
            "valid"
        };
        println!(
            "{:<10}  {:<8}  {:<20}  {}",
            &r.nonce.to_hex()[..8],
            status,
            r.issued_at.format("%Y-%m-%d %H:%M:%SZ"),
            r.name.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

/// Print the IP-exposure notice (ALWAYS — `sem_consent_notice_always_printed`), then prompt
/// unless `--yes`. Returns false if the user declined. `extra` is an optional second line
/// (the folder stage-1 "contents/size not yet known" wording, DESIGN §5).
fn consent_prompt(yes: bool, extra: Option<&str>, question: &str) -> Result<bool> {
    // MAS-INV-4: the notice prints unconditionally, before any prompt/skip logic runs.
    println!("{}", mascara_net::consent::IP_EXPOSURE_NOTICE);
    if let Some(line) = extra {
        println!("{line}");
    }
    if yes {
        return Ok(true);
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context("reading confirmation")?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// The **stage-2 start action** for a folder receive (DESIGN §5, amended 2026-07-27 — codex #5).
/// Mirrors [`consent_prompt`]'s shape deliberately: the disclosure line prints FIRST and
/// unconditionally — `--yes` folds the *question*, never the disclosure — so a scripted run is
/// never silent at the moment the second connection opens. Stage 1 already carried the full
/// [`IP_EXPOSURE_NOTICE`](mascara_net::consent::IP_EXPOSURE_NOTICE); this stage carries the short
/// reminder, because the second dial goes to the same sharer and discloses nothing new.
fn start_prompt(yes: bool, question: &str) -> Result<bool> {
    println!("{}", mascara_net::consent::IP_EXPOSURE_REMINDER);
    if yes {
        // Scripted: announce the action we are taking rather than going quiet.
        println!("{question} — proceeding (--yes).");
        return Ok(true);
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context("reading confirmation")?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Sum sender-declared entry sizes without overflowing (codex #13). A manifest can pass its
/// `root_hash` and cap checks while declaring `u64` sizes whose sum wraps — which would panic a
/// debug build and, worse, show a release user a wrong total on the consent screen.
fn checked_total(sizes: impl Iterator<Item = u64>) -> Result<u64> {
    let mut total: u64 = 0;
    for size in sizes {
        total = total.checked_add(size).ok_or_else(|| {
            anyhow::anyhow!("the declared entry sizes sum past u64 — refusing to show a wrapped total")
        })?;
    }
    Ok(total)
}

/// The receiver-side transfer log (`transfers/history.json`, D9) — what you hold, local-only.
fn history_log(home: &Path) -> HistoryLog<history::FileStore> {
    HistoryLog::new(history::FileStore::at(home))
}

/// Reuse an existing RESUMABLE record for this content (a resumed pull continues its history
/// entry, MR-7) or mint + record a fresh in-progress one. Returns the record id to complete.
///
/// Reuse is keyed by **content hash AND name** (codex #10): hash alone would adopt an unrelated
/// in-progress record for identical bytes offered under a different ticket/name, attributing that
/// transfer's state — and its retained origin — to this one.
fn record_started(
    log: &HistoryLog<history::FileStore>,
    name: &str,
    size: u64,
    sha256: [u8; 32],
    md5: [u8; 16],
    origin: &str,
) -> Result<TransferId> {
    if let Some(existing) = log
        .list()
        .context("reading the transfer history")?
        .into_iter()
        .find(|r| r.sha256 == sha256 && r.name == name && r.state.is_resumable())
    {
        return Ok(existing.id);
    }
    let id = TransferId::mint();
    log.record_in_progress(id, name.to_string(), size, sha256, md5, origin.to_string(), Utc::now())
        .context("recording the transfer start")?;
    Ok(id)
}

/// Post-transfer content check (D7/MT9): sniff the landed file's leading bytes against the
/// declared name/mime and report the three-way verdict. Warn-and-acknowledge mode — the M5
/// settings surface adds the hard-refuse knob (`verify_content_type` strictness, spec Data
/// Model); the sniff itself ALWAYS runs (`sem_fileref_type_is_claim_not_trust`). The result is
/// printed and dropped — never stored (`sem_content_opaque_no_retained_type`).
fn sniff_report(path: &Path, declared_name: &str, declared_mime: Option<&str>) {
    use std::io::Read as _;
    let mut head = vec![0u8; 64 * 1024];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) {
        Ok(n) => n,
        Err(_) => return, // the file just landed; a read failure here is not worth failing the transfer
    };
    match check_content(declared_name, declared_mime, &head[..n], ContentPolicy::WarnAndAcknowledge) {
        Ok(ContentVerdict::Match) => {}
        Ok(ContentVerdict::Unverifiable) => {
            eprintln!(
                "note: '{declared_name}' has no recognisable file signature (plain text/CSV/etc.) — \
                 its declared type cannot be checked, which is normal for such files."
            );
        }
        Ok(ContentVerdict::Mismatch { sniffed_ext, sniffed_mime, .. }) => {
            eprintln!(
                "WARNING: '{declared_name}' does not look like what it claims — the bytes sniff as \
                 {} ({}). The hash verified (you got exactly what was offered), but the offered \
                 content may be mislabeled. Do not open it unless you trust the sender.",
                sniffed_ext.as_deref().unwrap_or("unknown"),
                sniffed_mime.as_deref().unwrap_or("unknown mime"),
            );
        }
        Err(e) => eprintln!("note: content check skipped: {e}"),
    }
}

/// `recv <ticket>`: open → IP-exposure notice + consent → dial + pull into the current directory
/// (spec §CLI: no `--out`). A folder ticket runs the two-stage flow (DESIGN §5): stage 1 consents
/// to the dial + manifest fetch, the verified file list + total size is rendered white/greyed
/// against history (D9), and the pull starts only on the second explicit confirm (`--yes` folds
/// both, both notices still print).
async fn cmd_recv(home: &Path, ticket_str: &str, yes: bool) -> Result<()> {
    let (id, _created) = keystore::init_if_missing(home).context("loading/creating your identity")?;
    let ticket = Ticket::open(ticket_str, &id).context("opening the ticket")?;
    let dest = std::env::current_dir().context("resolving the current directory")?;
    let log = history_log(home);
    let origin = ticket.endpoint.addrs.join(",");

    match ticket.folder_ref() {
        None => {
            // Single file: one consent covers the transfer (size known pre-dial).
            if !consent_prompt(yes, None, "Continue?")? {
                eprintln!("Cancelled — nothing was downloaded.");
                return Ok(());
            }
            let ack = mascara_net::consent::acknowledge_ip_exposure();
            let file_ref =
                ticket.file_ref().expect("a non-folder ticket carries a file_ref").clone();
            let record_id = record_started(
                &log, &file_ref.name, file_ref.size, file_ref.sha256, file_ref.md5, &origin,
            )?;

            // `recv` only ever dials out — it needs no stable port (and can run alongside a
            // `serve` on the same box without a port conflict, unlike `build_endpoint`).
            let ep = mascara_net::endpoint::build_dialing_endpoint(&id)
                .await
                .context("binding the local transfer endpoint")?;
            let name = file_ref.name.clone();
            let result = mascara_net::dialer::pull(&ep, &ticket, ack, &dest, |done, total| {
                eprint!("\r{name}: {done}/{total} bytes");
                std::io::stderr().flush().ok();
            })
            .await;
            ep.close().await;
            eprintln!();

            let path = result.context("downloading the file")?;
            // Completion strips the origin from the record (MR-7) — the hash gate already ran.
            log.record_completed(record_id, Utc::now()).context("recording the completion")?;
            sniff_report(&path, &file_ref.name, file_ref.mime.as_deref());
            println!("Saved: {}", path.display());
            Ok(())
        }
        Some(folder_ref) => {
            let folder_name = folder_ref.name.clone();
            // Stage 1 (DESIGN §5): consent to the dial + manifest fetch — contents unknown yet.
            let stage1 = format!(
                "This is a FOLDER ticket ('{folder_name}'): fetching its file list opens the \
                 direct connection above; the folder's contents and total size are not yet known."
            );
            if !consent_prompt(yes, Some(&stage1), "Fetch the folder's file list?")? {
                eprintln!("Cancelled — nothing was fetched.");
                return Ok(());
            }
            let ack = mascara_net::consent::acknowledge_ip_exposure();
            let ep = mascara_net::endpoint::build_dialing_endpoint(&id)
                .await
                .context("binding the local transfer endpoint")?;

            let manifest =
                match mascara_net::dialer::fetch_manifest(&ep, &ticket, ack, &dest).await {
                    Ok(m) => m,
                    Err(e) => {
                        ep.close().await;
                        return Err(e).context("fetching the folder manifest");
                    }
                };

            // White/greyed (D9): an entry is "held" when a Completed history record carries its
            // hash AND the file is still where a pull would land it. Held entries are skipped
            // (no silent duplicate `name (2)` pulls); the re-download UX is the M5 GUI's.
            let held_hashes: std::collections::HashSet<[u8; 32]> = log
                .list()
                .context("reading the transfer history")?
                .into_iter()
                .filter(|r| matches!(r.state, TransferState::Completed { .. }))
                .map(|r| r.sha256)
                .collect();
            let is_held = |e: &ManifestEntry| {
                held_hashes.contains(&e.sha256) && dest.join(&e.rel_path).is_file()
            };

            // codex #13: declared sizes are sender-controlled — sum them checked, and refuse
            // BEFORE showing a consent summary rather than displaying a wrapped total.
            let total = checked_total(manifest.entries.iter().map(|e| e.size))
                .context("this folder's declared sizes are not a sane total")?;
            let to_pull: Vec<ManifestEntry> =
                manifest.entries.iter().filter(|e| !is_held(e)).cloned().collect();
            let pull_bytes = checked_total(to_pull.iter().map(|e| e.size))
                .context("this folder's declared sizes are not a sane total")?;

            println!("\nFolder '{folder_name}' — {} files, {total} bytes:", manifest.entries.len());
            for e in &manifest.entries {
                let mark = if is_held(e) { "held" } else { "new " };
                println!("  [{mark}] {:>12}  {}", e.size, e.rel_path);
            }
            if to_pull.is_empty() {
                ep.close().await;
                println!("Everything in this folder is already held — nothing to download.");
                return Ok(());
            }

            // Stage 2 (DESIGN §5 / chorus H6): the pull starts only on an explicit start action,
            // taken with the file list and total above already in view. `start_prompt` always
            // prints the second-connection reminder — `--yes` folds the question, not the
            // disclosure (codex #5).
            let question = format!("Download {} file(s), {pull_bytes} bytes?", to_pull.len());
            let proceed = start_prompt(yes, &question)?;
            if !proceed {
                ep.close().await;
                eprintln!("Cancelled — the file list was fetched, no file bytes were downloaded.");
                return Ok(());
            }
            let ack2 = mascara_net::consent::acknowledge_ip_exposure();

            let mut record_ids = std::collections::HashMap::with_capacity(to_pull.len());
            for e in &to_pull {
                record_ids.insert(
                    e.rel_path.clone(),
                    record_started(&log, &e.rel_path, e.size, e.sha256, e.md5, &origin)?,
                );
            }

            // Complete each entry's history record AS IT LANDS (codex #8). A folder pull can fail
            // partway; recording only after the whole pull returned left every already-finished
            // file stuck "in progress" — still holding its origin, against MR-7 — despite being
            // verified on disk. The callback also drives the per-entry sniff, so both happen for
            // files that completed before a later entry failed.
            let mut landed: Vec<(String, PathBuf)> = Vec::new();
            let mut record_errors: Vec<String> = Vec::new();
            let pull_manifest = Manifest { v: manifest.v, entries: to_pull.clone() };
            let result = mascara_net::dialer::pull_folder(
                &ep,
                &ticket,
                ack2,
                &pull_manifest,
                &dest,
                |rel, done, total| {
                    eprint!("\r{rel}: {done}/{total} bytes          ");
                    std::io::stderr().flush().ok();
                },
                |entry, path| {
                    if let Some(id) = record_ids.get(&entry.rel_path) {
                        // The transfer itself succeeded; a history write failure must not discard
                        // that fact, so collect it and surface it after the pull instead.
                        if let Err(e) = log.record_completed(*id, Utc::now()) {
                            record_errors
                                .push(format!("could not record {}: {e}", entry.rel_path));
                        }
                    }
                    landed.push((entry.rel_path.clone(), path.to_path_buf()));
                },
            )
            .await;
            ep.close().await;
            eprintln!();

            // Report what landed before propagating any failure — those files are verified and
            // kept, and the user needs to know which.
            for (rel, path) in &landed {
                sniff_report(path, rel, None);
            }
            for e in &record_errors {
                eprintln!("note: {e}");
            }
            match result {
                Ok(paths) => {
                    println!("Saved {} file(s) under {}", paths.len(), dest.display());
                    Ok(())
                }
                Err(e) => {
                    if !landed.is_empty() {
                        println!(
                            "Saved {} of {} file(s) under {} before the transfer stopped.",
                            landed.len(),
                            to_pull.len(),
                            dest.display()
                        );
                    }
                    Err(e).context("downloading the folder")
                }
            }
        }
    }
}

/// `history [--purge]` (spec §CLI, D9): what you hold, local-only, yours to discard. Origin shows
/// only while a transfer is resumable (MR-7 — completed rows have none to show).
fn cmd_history(home: &Path, purge: bool) -> Result<()> {
    let log = history_log(home);
    if purge {
        log.purge_all().context("purging the transfer history")?;
        eprintln!("Transfer history purged.");
        return Ok(());
    }
    let records = log.list().context("reading the transfer history")?;
    if records.is_empty() {
        println!("No transfers recorded yet.");
        return Ok(());
    }
    println!("{:<10}  {:<11}  {:>12}  NAME", "ID", "STATE", "SIZE");
    for r in records {
        let state = match &r.state {
            TransferState::InProgress { .. } => "in-progress",
            TransferState::Partial { .. } => "partial",
            TransferState::Completed { .. } => "completed",
        };
        println!("{:<10}  {:<11}  {:>12}  {}", &r.id.to_hex()[..8], state, r.size, r.name);
    }
    Ok(())
}

/// `serve`: run the transfer listener in the foreground until Ctrl-C (spec §CLI, D-serve).
async fn cmd_serve(home: &Path) -> Result<()> {
    let (id, _created) = keystore::init_if_missing(home).context("loading/creating your identity")?;
    let ep = mascara_net::endpoint::build_endpoint(&id).await.context("binding the local transfer endpoint")?;
    eprintln!("Serving as {} — Ctrl-C to stop.", hex::encode(ep.id().as_bytes()));

    tokio::select! {
        res = mascara_net::listener::run(ep.clone(), home.to_path_buf()) => {
            res.context("listener error")?;
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("Stopping…");
        }
    }
    ep.close().await;
    Ok(())
}
