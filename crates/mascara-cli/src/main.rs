//! `mascara` — the Phase-1 CLI, a thin front-end over `mascara-core`/`mascara-net` (DESIGN.md §8).
//! M2 surface: `card`, `send`, `tickets`, `recv`, `serve` — the actual transfer, gated by the
//! IP-exposure consent (`mascara-net::consent`, MAS-INV-4).
//!
//! MAS-INV-1: nothing here reaches a Hoardbook `npub`; the identity is Mascara's own.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use mascara_core::registry::IssuedRecord;
use mascara_core::{keystore, Card, FileStore, Nonce, Registry, ShareDescriptor, Ticket};

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
        /// The actual file on THIS device to serve for this ticket. Kept local-only — never
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

    let name = descriptor.name.clone();
    let size = descriptor.size;
    let nonce = Nonce::mint();
    let ticket = descriptor.into_file_ticket(endpoint, id.card().transport_pk, None, nonce);
    let sealed = ticket.seal(&recipient).context("sealing the ticket to the recipient's card")?;

    // Record the nonce BEFORE emitting the ticket, so nothing we hand out is unrecorded/unrevokable.
    // The stored recipient_transport_pk is the *recipient's* transport pk — a disposable endpoint the
    // M2 listener needs for anti-replay, dropped on revoke/expire (MR-8).
    let registry = Registry::new(FileStore::at(home));
    registry
        .issue(IssuedRecord::new(nonce, Some(name.clone()), Utc::now(), None, recipient.transport_pk))
        .context("recording the issued ticket")?;

    // Local-only bookkeeping: where do the bytes actually live for this nonce (never sealed,
    // never sent — see the M2 HANDOVER deviation note on `--file`). `serve` reads this at
    // request time.
    let offers = mascara_net::listener::OfferStore::at(home);
    offers
        .record(mascara_net::listener::OfferRecord {
            nonce,
            path: file.to_path_buf(),
            file_ref: ticket.file_ref.clone(),
            grant: ticket.grant,
        })
        .context("recording the local file source for this ticket")?;

    // Paste-only: the sealed ticket string goes to stdout. The `.mascara` file carrier is dropped
    // (MR-9) — a saved ticket file re-introduces origin (MR-7/8) and an auto-launch surface.
    println!("{sealed}");
    eprintln!(
        "Issued ticket {} for '{}' ({} bytes). Revoke with: mascara tickets --revoke {}",
        &nonce.to_hex()[..8],
        name,
        size,
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

/// `recv <ticket>`: open → print the IP-exposure notice (ALWAYS, even with `--yes` —
/// `sem_consent_notice_always_printed`) → prompt (unless `--yes`) → construct the `ConsentAck` →
/// dial + pull into the current directory (spec §CLI: no `--out`, matching the documented Phase-1
/// surface).
async fn cmd_recv(home: &Path, ticket_str: &str, yes: bool) -> Result<()> {
    let (id, _created) = keystore::init_if_missing(home).context("loading/creating your identity")?;
    let ticket = Ticket::open(ticket_str, &id).context("opening the ticket")?;

    // MAS-INV-4: the notice prints unconditionally, before any prompt/skip logic runs.
    println!("{}", mascara_net::consent::IP_EXPOSURE_NOTICE);
    if !yes {
        eprint!("Continue? [y/N] ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).context("reading confirmation")?;
        if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
            eprintln!("Cancelled — nothing was downloaded.");
            return Ok(());
        }
    }
    let ack = mascara_net::consent::acknowledge_ip_exposure();

    // `recv` only ever dials out — it needs no stable port (and can run alongside a `serve` on
    // the same box without a port conflict, unlike `build_endpoint`).
    let ep = mascara_net::endpoint::build_dialing_endpoint(&id)
        .await
        .context("binding the local transfer endpoint")?;
    let dest = std::env::current_dir().context("resolving the current directory")?;
    let name = ticket.file_ref.name.clone();

    let result = mascara_net::dialer::pull(&ep, &ticket, ack, &dest, |done, total| {
        eprint!("\r{name}: {done}/{total} bytes");
        std::io::stderr().flush().ok();
    })
    .await;
    ep.close().await;
    eprintln!();

    let path = result.context("downloading the file")?;
    println!("Saved: {}", path.display());
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
