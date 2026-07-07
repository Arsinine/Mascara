//! mascara-transfer — file-transfer code preserved VERBATIM from Hoardbook (v0.9.0 `hb-app`).
//!
//! These modules were moved here intact when Hoardbook's spec (v0.9.5 / v0.9.6) cut in-app file
//! transfer (finding H4 / Hoardbook INV-4: "Hoardbook moves no files"). Per the move decision
//! ("verbatim now, refactor later"), nothing was rewritten — the working code is preserved here as
//! the starting point for the Mascara refactor described in `../../MASCARA_SPEC.md`.
//!
//! ## Why the modules are not declared yet
//! As copied, they still reference Hoardbook's `crate::` paths (`DataStore`, `SharedIdentity`,
//! `SharedEndpoint`, `presence`, `commands::sharing`) and reuse the **Hoardbook `npub`** for the
//! binding token — which directly violates Mascara MAS-INV-1 (separate identity). So they will not
//! compile as-is and are intentionally left commented out below.
//!
//! ## Refactor TODO (to wire this up + match the Mascara spec)
//! - **MAS-INV-1:** switch the transport identity OFF the Hoardbook `npub` to Mascara's OWN keypair.
//! - **MAS-INV-3:** replace presence-binding address resolution (`transfer::resolve_peer_addr`) with
//!   the sealed **transfer-ticket** model — the address rides a sealed, ephemeral, recipient-scoped
//!   ticket, never a published presence event.
//! - **MAS-INV-4:** add the first-class IP-private (iroh-relay / Tor) transport choice + per-transfer
//!   IP-exposure consent.
//! - Re-home the `crate::` references onto Mascara's own app shell; extract the transfer-only
//!   functions out of the `from-hb-app/` reference sources.
//!
//! ## Preserved source (beside this file)
//! - `transfer.rs`  — the `/hoardbook/xfer/1` protocol: `XFER_ALPN`, `handle_xfer_stream` (H17
//!                    binding-token gate), `download_file(_inner)` (H2), `resolve_peer_addr`,
//!                    SHA-256 integrity check. Repurpose per MASCARA_SPEC §Transport.
//! - `conn.rs`      — connection-drain helper (xfer error-response survives connection close).
//! - `p2p_it.rs`    — the L3 geo-manual integration harness (serve / probe / backup / restore).
//! - `from-hb-app/` — the entangled hb-app sources kept WHOLE so the transfer-only functions can be
//!                    extracted without re-deriving them: `presence.rs` (`publish_presence` +
//!                    address seal), `sharing.rs` (`request_download` / `cancel_download`),
//!                    `identity_state.rs` + `store.rs` (the `iroh_secret` 3rd key), `lib.rs`
//!                    (`start_iroh_endpoint` / `run_accept_loop`).
//!
//! `hb-core` (incl. `gate` = binding token, `binding` = sealed address) and `hb-net` (the relay
//! client) are copied wholesale into this workspace as preserved dependencies; the refactor will
//! trim them to Mascara's needs and graft Mascara's own identity.

// Intentionally NOT declared yet — they do not compile as-is (see Refactor TODO above).
// Uncomment + re-home during the Mascara refactor:
// pub mod transfer;
// pub mod conn;
// pub mod p2p_it;
