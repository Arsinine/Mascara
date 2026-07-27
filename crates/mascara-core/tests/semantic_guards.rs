//! Semantic guards — architecture fitness functions, run as ordinary `cargo test`
//! (SEMANTIC_MODEL.md, Tier A). One invariant = one test; a failing guard is a *real*
//! architecture finding and is never weakened to pass (SEMANTIC_MODEL.md "Rules of the game" #4).
//!
//! These are **source-tree sweeps**: each test walks the shipped `.rs` / `Cargo.toml` files and
//! asserts a property over the code itself, so `cargo test` stays the single gate.
//!
//! **Why the sweeps strip `//` comments.** The Tier A rows are phrased over "**symbol**s" — code
//! identifiers (a `use`, a type, a call), not words in prose. A doc comment that *names* an
//! invariant to explain it ("this is never the Hoardbook `npub`") documents the mechanism's
//! *absence*; it does not re-introduce the mechanism. Matching prose would flag the very comments
//! that describe the guarantee — a false positive, not a finding. So the sweeps drop `//`
//! line/doc comments and match against code only. Real code violations (e.g. `use nostr_sdk::…`
//! in `identity.rs`) survive stripping and still trip the guard.
//!
//! Scope: guards the invariant surfaces that exist today. The product reworks MR-8 (registry
//! recipient-pk), MR-13 (remove send-side hashing) and MR-22 (`ShareDescriptor`) are now landed and
//! guarded below (`sem_registry_no_durable_recipient`, `sem_mascara_no_commitment_hashing`,
//! `sem_ticket_built_from_descriptor`).

use std::path::{Path, PathBuf};

/// The `mascara-core` crate root — this test crate's manifest dir.
fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The `mascara-cli` crate root — sibling of `mascara-core` under `crates/`.
fn cli_dir() -> PathBuf {
    core_dir()
        .parent()
        .expect("mascara-core has a parent `crates/` dir")
        .join("mascara-cli")
}

/// The `mascara-net` crate root — sibling of `mascara-core` under `crates/` (M2).
fn net_dir() -> PathBuf {
    core_dir()
        .parent()
        .expect("mascara-core has a parent `crates/` dir")
        .join("mascara-net")
}

/// The `mascara-it` crate root — sibling of `mascara-core` under `crates/` (M2).
fn it_dir() -> PathBuf {
    core_dir()
        .parent()
        .expect("mascara-core has a parent `crates/` dir")
        .join("mascara-it")
}

/// Recursively collect every `.rs` file under `dir`.
fn rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(rs_files(&path));
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    out
}

/// Drop a `//` line/doc comment from one line, keeping the code before it (see module docs). This
/// tree has no block comments and no target symbol hidden behind a `//`-in-a-string-literal, so the
/// truncate-at-first-`//` heuristic is exact here.
fn code_line(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Comment-stripped view of a whole source file.
fn code_only(src: &str) -> String {
    src.lines().map(code_line).collect::<Vec<_>>().join("\n")
}

/// MAS-INV-1 — the Mascara identity never reuses / derives from the hoard `npub`, and the whole
/// hoard-key mechanism (`nostr` / `npub` / `secp256k1` / schnorr) is **confined to the verify-only
/// `assertion` module**, its single sanctioned exception.
///
/// Guards `sem_identity_never_reuses_hoard_npub` **and folds in `sem_link_confined_to_module`**
/// (SEMANTIC_MODEL.md, Tier A). Sources: DOMAIN_MODEL.md — Identity MUST NOT "be, or derive from,
/// the Hoardbook `npub`/keys"; LinkAssertion keeps "the `secp256k1`/`npub` mechanism … confined to
/// the `assertion` module (the MAS-INV-1 absence-sweep exemption)".
#[test]
fn sem_identity_never_reuses_hoard_npub() {
    // Matched case-insensitively so `Nostr` / `Schnorr` / `NPUB` are all caught.
    const FORBIDDEN: [&str; 4] = ["nostr", "npub", "secp256k1", "schnorr"];
    // The single MAS-INV-1 exception: the verify-only assertion module.
    let allow = core_dir().join("src").join("assertion.rs");

    let mut swept = 0usize;
    let mut violations: Vec<String> = Vec::new();
    // M2 (mascara-net/mascara-it) joins the swept tree per TEST_PLAN §3's "sweep definition" note
    // and the M2 brief's "extend the nostr absence sweep to cover the new crates" instruction.
    for dir in [core_dir().join("src"), cli_dir().join("src"), net_dir().join("src"), it_dir().join("src")] {
        for file in rs_files(&dir) {
            if file == allow {
                continue;
            }
            swept += 1;
            let src = std::fs::read_to_string(&file).unwrap();
            for (idx, raw) in src.lines().enumerate() {
                let code = code_line(raw).to_lowercase();
                for sym in FORBIDDEN {
                    if code.contains(sym) {
                        violations.push(format!("  {}:{} — `{sym}`", file.display(), idx + 1));
                    }
                }
            }
        }
    }

    assert!(swept > 0, "swept no .rs files — the path wiring is broken");
    assert!(
        violations.is_empty(),
        "MAS-INV-1: hoard-key symbol(s) leaked outside the `assertion` module:\n{}",
        violations.join("\n")
    );
}

/// MAS-INV-5 / MR-22 — Mascara has **no runtime Hoardbook dependency**. Neither `mascara-core` nor
/// `mascara-cli` depends on `hb-core` / `hb-net` / anything Hoardbook (their `Cargo.toml`s), and no
/// `hb_core` / `hb_net` / `hoardbook` import appears in their `src/`. The only seam is the one-way
/// `ShareDescriptor` (MR-22) that Mascara *consumes* — it never calls Hoardbook at runtime.
///
/// Guards `sem_mascara_no_runtime_hoardbook_dep` (SEMANTIC_MODEL.md, Tier A).
#[test]
fn sem_mascara_no_runtime_hoardbook_dep() {
    // Crate names as they appear in a manifest (`hb-core`) or in Rust code (`hb_core`).
    const DEP_FORMS: [&str; 5] = ["hb-core", "hb-net", "hb_core", "hb_net", "hoardbook"];

    // (a) Neither manifest declares a Hoardbook dependency (TOML `#` comments stripped).
    for manifest in [core_dir().join("Cargo.toml"), cli_dir().join("Cargo.toml")] {
        let src = std::fs::read_to_string(&manifest).unwrap();
        for (idx, raw) in src.lines().enumerate() {
            let line = match raw.find('#') {
                Some(i) => &raw[..i],
                None => raw,
            }
            .to_lowercase();
            for dep in DEP_FORMS {
                assert!(
                    !line.contains(dep),
                    "MAS-INV-5: {} declares a Hoardbook dependency at line {}: {}",
                    manifest.display(),
                    idx + 1,
                    raw.trim()
                );
            }
        }
    }

    // (b) No Hoardbook crate/module import in either `src` tree. Case-sensitive lowercase crate
    // identifiers — the product *word* "Hoardbook" appears legitimately in prose/UX strings and is
    // not an import.
    const IMPORT_FORMS: [&str; 3] = ["hb_core", "hb_net", "hoardbook"];
    let mut violations: Vec<String> = Vec::new();
    for dir in [core_dir().join("src"), cli_dir().join("src")] {
        for file in rs_files(&dir) {
            let src = std::fs::read_to_string(&file).unwrap();
            for (idx, raw) in src.lines().enumerate() {
                let code = code_line(raw);
                for dep in IMPORT_FORMS {
                    if code.contains(dep) {
                        violations.push(format!("  {}:{} — `{dep}`", file.display(), idx + 1));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "MAS-INV-5: Hoardbook import(s) in Mascara src:\n{}",
        violations.join("\n")
    );
}

/// Secret-holding identity types expose **no** `Debug` / `Display` — secret material never renders
/// into a log line, panic message, or error string (DOMAIN_MODEL.md — Identity MUST NOT "expose
/// secret material — no `Debug`/`Display` on secret types; secrets never serialize in clear").
///
/// Guards the `Debug`/`Display` clause of `sem_identity_secrets_never_exposed`
/// (SEMANTIC_MODEL.md, Tier A). The encrypted-at-rest / no-clear-serialize clauses of that row are
/// covered by the keystore's own unit tests (0600 perms, atomic writes) and are not re-checked here.
///
/// Today's secret-holding types (inspected in `identity.rs` + `keystore.rs`):
///   - `Identity`  — holds the ed25519 transport `SigningKey` + the X25519 sealing `StaticSecret`.
///   - `KeysFile`  — the on-disk `keys.json` shape; holds the hex transport/sealing secrets.
///
/// A new secret type must be added to this list (and, like these, derive neither trait).
#[test]
fn sem_identity_secrets_never_exposed() {
    let checks = [
        (core_dir().join("src").join("identity.rs"), "Identity"),
        (core_dir().join("src").join("keystore.rs"), "KeysFile"),
    ];

    for (file, ty) in checks {
        let src = std::fs::read_to_string(&file).unwrap();

        // (a) No `#[derive(…)]` naming Debug/Display on the type.
        let derives = derives_above(&src, ty);
        for bad in ["Debug", "Display"] {
            assert!(
                !derives.contains(bad),
                "{}: secret-holding type `{}` derives `{}` — it must derive neither.",
                file.display(),
                ty,
                bad
            );
        }

        // (b) No *manual* `impl … Debug/Display for <ty>` either (comments stripped).
        let code = code_only(&src);
        for bad in ["Debug", "Display"] {
            let needle = format!("{bad} for {ty}");
            assert!(
                !code.contains(&needle),
                "{}: secret-holding type `{}` has a manual `impl {}` — it must expose neither trait.",
                file.display(),
                ty,
                needle
            );
        }
    }
}

/// Collect the `#[derive(…)]` attribute lines immediately above the declaration of `struct <ty>`.
/// Walks upward past blank lines, attributes and doc/line comments; stops at the first real code
/// line above the item. Panics if the struct is not found (the secret-type list is then stale).
fn derives_above(src: &str, ty: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let needle = format!("struct {ty}");
    let decl = lines
        .iter()
        .position(|l| {
            let t = l.trim_start();
            match t.find(&needle) {
                Some(pos) => {
                    // Word boundary after the name so `struct Identity` != `struct IdentityFoo`.
                    let after = t[pos + needle.len()..].chars().next();
                    matches!(after, Some(' ') | Some('{') | Some('<') | None)
                }
                None => false,
            }
        })
        .unwrap_or_else(|| panic!("could not find `struct {ty}` — secret-type sweep is out of date"));

    let mut derives = String::new();
    let mut i = decl;
    while i > 0 {
        i -= 1;
        let t = lines[i].trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('#') {
            if t.contains("derive") {
                derives.push_str(t);
                derives.push('\n');
            }
            continue;
        }
        if t.starts_with("//") {
            continue; // doc / line comment attached to the item
        }
        break; // reached real code above the attribute block
    }
    derives
}

/// MR-22 — a ticket's content commitment **originates in the `ShareDescriptor`**, never a Mascara
/// computation. Behavioural: a file descriptor round-trips from JSON and `descriptor.file_ref()`
/// yields a `FileRef` whose `sha256`/`md5` are the ones the descriptor *carried*. Structural:
/// `ticket.rs` contains no `from_path` (send-side hashing is gone).
///
/// Guards `sem_ticket_built_from_descriptor` (SEMANTIC_MODEL.md, Tier A; MR-13/MR-22). Source:
/// DOMAIN_MODEL "The seam — ShareDescriptor" — Mascara "consumes it, caches the hash … serves
/// independently", and "does not compute" the commitment.
#[test]
fn sem_ticket_built_from_descriptor() {
    use mascara_core::ShareDescriptor;

    // (a) Behaviour: hashes are carried from the descriptor into the FileRef, not recomputed.
    let json = format!(
        r#"{{ "kind": "file", "name": "m.mkv", "size": 42, "sha256": "{}", "md5": "{}",
              "mime": null, "link_assertion": null }}"#,
        hex::encode([0xABu8; 32]),
        hex::encode([0xCDu8; 16]),
    );
    let d = ShareDescriptor::from_json_str(&json).expect("a well-formed descriptor must parse");
    let ShareDescriptor::File(file) = d else { panic!("expected the file variant") };
    let fr = file.file_ref();
    assert_eq!(fr.sha256, [0xABu8; 32], "sha256 must be the descriptor's, carried not computed");
    assert_eq!(fr.md5, [0xCDu8; 16], "md5 must be the descriptor's, carried not computed");
    assert_eq!((fr.name.as_str(), fr.size), ("m.mkv", 42));

    // (b) Structural: no `from_path` survives in ticket.rs (comment-stripped, so the doc note that
    // *names* its removal does not count as a re-introduction).
    let ticket_src = std::fs::read_to_string(core_dir().join("src").join("ticket.rs")).unwrap();
    assert!(
        !code_only(&ticket_src).contains("from_path"),
        "MR-13: `from_path` (send-side hashing) must not reappear in ticket.rs"
    );
}

/// MR-13 — Mascara computes **no** content commitment at ticket-creation. Source sweep: no
/// content-hash crate import (`use sha2` / `use md5` / `use sha1` / `use blake3`) appears in
/// `ticket.rs` — the ticket body's per-file commitment is carried from the `ShareDescriptor`,
/// never computed.
///
/// `share.rs` is **not** swept here at M3 stage 2: a folder descriptor's
/// [`crate::FolderDescriptor::verify_root_hash`] computes `sha256(manifest bytes)` to consistency-
/// check **Hoardbook's own two claims** (its entries vs its declared `root_hash`) before minting a
/// folder ticket — that is verifying a carried commitment, not originating one (the per-entry
/// sha256/md5 are still carried, never computed). The manifest's own `root_hash`/`verify` helpers
/// in `manifest.rs` were never swept either, for the same reason. The per-file sha256/md5 in a
/// `FileRef`/`ManifestEntry` remain carried values, never computed.
///
/// (Note: `assertion.rs` legitimately hashes the link-assertion *message* with sha2 and is out of
/// scope — that is domain-separation for a signature, not a content commitment. This guard is about
/// the ticket-creation path only.)
///
/// Guards `sem_mascara_no_commitment_hashing` (SEMANTIC_MODEL.md, Tier A; MR-13).
#[test]
fn sem_mascara_no_commitment_hashing() {
    const HASH_IMPORTS: [&str; 4] = ["use sha2", "use md5", "use sha1", "use blake3"];
    let mut violations: Vec<String> = Vec::new();
    // Only ticket.rs is swept: ticket-body content commitments (per-file sha256/md5) must be
    // carried, never computed. share.rs's manifest root_hash consistency check is a verify, not a
    // commitment origin (see the test's module doc above); manifest.rs is unswept for the same
    // reason.
    let path = core_dir().join("src").join("ticket.rs");
    let src = std::fs::read_to_string(&path).unwrap();
    for (idx, raw) in code_only(&src).lines().enumerate() {
        for imp in HASH_IMPORTS {
            if raw.contains(imp) {
                violations.push(format!("  {}:{} — `{imp}`", path.display(), idx + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "MR-13: content-hash crate import(s) in ticket.rs (the per-file commitment must be carried, not computed):\n{}",
        violations.join("\n")
    );
}

/// MR-8 — the recipient `transport_pk` is kept only while a nonce is **active** and dropped on
/// revoke/expire: no durable who-got-what log, no recipient card/`npub`. Behavioural: issue → `Some`;
/// revoke → `None`; a past-expiry record loses it on `compact(now)`.
///
/// Guards `sem_registry_no_durable_recipient` (SEMANTIC_MODEL.md, Tier A; MR-8). Source:
/// DOMAIN_MODEL MR-8 — "dropped on revoke/expire … No durable 'sent F to P at T' record".
#[test]
fn sem_registry_no_durable_recipient() {
    use chrono::{Duration, Utc};
    use mascara_core::{IssuedRecord, IssuedTickets, Nonce};

    let now = Utc::now();
    let pk = [0x22u8; 32];

    // Active nonce keeps the recipient endpoint...
    let r = IssuedRecord::new(Nonce::mint(), Some("f.bin".into()), now, None, pk);
    let nonce = r.nonce;
    let mut t = IssuedTickets::default();
    t.issue(r).unwrap();
    assert_eq!(
        t.tickets[0].recipient_transport_pk,
        Some(pk),
        "an active nonce keeps the recipient transport pk (M2 anti-replay needs it)"
    );

    // ...and drops it on revoke.
    t.revoke(&nonce).unwrap();
    assert_eq!(
        t.tickets[0].recipient_transport_pk, None,
        "MR-8: revoke drops the recipient endpoint — no durable who-got-what record"
    );

    // A past-expiry record loses it on compaction (revoked OR expired ⇒ dropped).
    let expired =
        IssuedRecord::new(Nonce::mint(), Some("g.bin".into()), now, Some(now - Duration::hours(1)), pk);
    let mut t2 = IssuedTickets::default();
    t2.issue(expired).unwrap();
    assert_eq!(t2.tickets[0].recipient_transport_pk, Some(pk), "carried while stored, before compaction");
    t2.compact(now);
    assert_eq!(
        t2.tickets[0].recipient_transport_pk, None,
        "MR-8: compaction drops the recipient endpoint for expired (invalid) nonces"
    );
}

/// MR-9 / D2 — **ticket delivery is copy/paste only**; the `.mascara` file carrier is dropped. A
/// saved ticket file re-introduces origin (against MR-7/8) and adds an auto-launch/phishing surface
/// (DOMAIN_MODEL.md MR-9; DESIGN.md §8). This guards against a convenience file-carrier returning —
/// the `--out .mascara` flag HANDOVER M1 documented and MR-9 later banned.
///
/// Two source-tree sweeps (comments stripped, so the doc notes that *name* the dropped carrier — e.g.
/// `ticket.rs`' "a `.mascara` file is the same string" — do not count as a re-introduction):
///   (a) No `.mascara` file literal in code. The **one sanctioned** `.mascara` is the home-directory
///       join `~/.mascara` (`keystore.rs`, the config dir — not a ticket file); it is exempted by
///       matching the `join(".mascara")` construction, mirroring the MAS-INV-1 `assertion.rs`
///       exemption. A returning `--out foo.mascara` default trips this.
///   (b) The CLI writes no file — `mascara-cli/src` contains no `fs::write` / `File::create` /
///       `OpenOptions`. The sealed ticket leaves only via stdout (`println!`), so a `--out <path>`
///       carrier of *any* extension trips this. If a legitimate CLI file-write is ever needed, this
///       failing IS the MR-9 tripwire — re-derive against MR-7/8, never weaken (SEMANTIC_MODEL.md
///       "Rules of the game" #4).
///
/// Guards `sem_ticket_delivery_paste_only` (SEMANTIC_MODEL.md, Tier A; MR-9/D2).
#[test]
fn sem_ticket_delivery_paste_only() {
    // (a) No `.mascara` file literal in code, except the sanctioned `~/.mascara` home-dir join.
    let mut carriers: Vec<String> = Vec::new();
    let mut swept = 0usize;
    for dir in [core_dir().join("src"), cli_dir().join("src")] {
        for file in rs_files(&dir) {
            swept += 1;
            let src = std::fs::read_to_string(&file).unwrap();
            for (idx, raw) in src.lines().enumerate() {
                let code = code_line(raw);
                if code.contains(".mascara") && !code.contains("join(\".mascara\")") {
                    carriers.push(format!("  {}:{} — `.mascara` file literal", file.display(), idx + 1));
                }
            }
        }
    }
    assert!(swept > 0, "swept no .rs files — the path wiring is broken");
    assert!(
        carriers.is_empty(),
        "MR-9: a `.mascara` ticket-file carrier reappeared in code (delivery is paste-only):\n{}",
        carriers.join("\n")
    );

    // (b) The CLI writes no file — the sealed ticket leaves only via stdout.
    const FILE_WRITES: [&str; 3] = ["fs::write", "File::create", "OpenOptions"];
    let mut cli_writes: Vec<String> = Vec::new();
    for file in rs_files(&cli_dir().join("src")) {
        let src = std::fs::read_to_string(&file).unwrap();
        for (idx, raw) in code_only(&src).lines().enumerate() {
            for w in FILE_WRITES {
                if raw.contains(w) {
                    cli_writes.push(format!("  {}:{} — `{w}`", file.display(), idx + 1));
                }
            }
        }
    }
    assert!(
        cli_writes.is_empty(),
        "MR-9: the CLI writes a file — a ticket file-carrier of any extension is banned (paste-only):\n{}",
        cli_writes.join("\n")
    );
}

// ============================================================================================
// M2 guards (mascara-net comes up this milestone — DESIGN §4/§5/§6; SEMANTIC_MODEL PINNED rows
// that convert to ENFORCED "in the slice that creates the surface", per the tripwire rule).
// ============================================================================================

/// MAS-INV-3 / D1, M2 form — `mascara-net`'s endpoint is built with discovery off both
/// directions **by construction**: every endpoint uses `presets::Minimal` (zero address-lookup
/// services), never `presets::N0` (which adds pkarr/DNS) and never `.address_lookup(...)`; relay
/// is always `RelayMode::Disabled`, never `Default`/`Custom`/`Staging`. Source sweep
/// (comment-stripped, so the module docs that *name* what's avoided don't self-trip).
///
/// Guards `sem_no_discovery_publish_or_consume`'s **M2 (static/construction-time) form**
/// (SEMANTIC_MODEL.md, Tier A) — status **PARTIAL**: the *continuous* runtime enforcement (the §6
/// live path-type watcher; a mid-session relay flip aborting the transfer) is M4 and stays
/// PINNED. Behavioural companion: `mascara-net/src/endpoint.rs`'s
/// `loopback_endpoint_binds_and_reports_an_addr` test proves a real bound endpoint reports only
/// direct (`Ip`) addresses.
#[test]
fn sem_no_discovery_publish_or_consume() {
    const FORBIDDEN: [&str; 4] =
        ["presets::n0", ".address_lookup(", "relaymode::default", "relaymode::custom"];
    // `RelayMode::Staging` checked separately (case variants below cover it via the same const).
    const FORBIDDEN2: [&str; 1] = ["relaymode::staging"];

    let mut swept = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for file in rs_files(&net_dir().join("src")) {
        swept += 1;
        let src = std::fs::read_to_string(&file).unwrap();
        for (idx, raw) in src.lines().enumerate() {
            let code = code_line(raw).to_lowercase();
            for sym in FORBIDDEN.iter().chain(FORBIDDEN2.iter()) {
                if code.contains(sym) {
                    violations.push(format!("  {}:{} — `{sym}`", file.display(), idx + 1));
                }
            }
        }
    }
    assert!(swept > 0, "swept no mascara-net .rs files — the path wiring is broken");
    assert!(
        violations.is_empty(),
        "MAS-INV-3/D1: a discovery-publishing/consuming or non-Disabled relay config appeared in mascara-net:\n{}",
        violations.join("\n")
    );

    // And the positive half: every endpoint construction really does set `presets::Minimal` +
    // `RelayMode::Disabled` explicitly — an endpoint built with neither line present would be a
    // silent regression this sweep's negative-only check couldn't catch.
    let endpoint_src = std::fs::read_to_string(net_dir().join("src").join("endpoint.rs")).unwrap();
    let code = code_only(&endpoint_src);
    assert!(code.contains("presets::Minimal"), "endpoint.rs must build on presets::Minimal");
    assert!(code.contains("RelayMode::Disabled"), "endpoint.rs must always set RelayMode::Disabled");
}

/// MAS-INV-3 — the sender's gathered addresses exist **only** inside the sealed ticket body,
/// never emitted anywhere else (a sibling guarantee to `sem_card_never_published`, for the
/// address rather than the card). Two source sweeps:
/// (a) `mascara-net` contains **no** print/log macro call at all — nothing there could ever
///     leak a gathered address, since nothing prints anything.
/// (b) `mascara-cli`'s only use of the gathered addresses feeds directly into the ticket
///     (`into_file_ticket`) — no print/log statement in the CLI mentions the endpoint/address
///     data.
///
/// Guards `sem_ticket_endpoint_only_sealed` (SEMANTIC_MODEL.md, Tier B).
#[test]
fn sem_ticket_endpoint_only_sealed() {
    const PRINT_MACROS: [&str; 4] = ["println!", "eprintln!", "print!", "tracing::"];

    let mut swept = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for file in rs_files(&net_dir().join("src")) {
        swept += 1;
        let src = std::fs::read_to_string(&file).unwrap();
        for (idx, raw) in code_only(&src).lines().enumerate() {
            for m in PRINT_MACROS {
                if raw.contains(m) {
                    violations.push(format!("  {}:{} — `{m}`", file.display(), idx + 1));
                }
            }
        }
    }
    assert!(swept > 0, "swept no mascara-net .rs files — the path wiring is broken");
    assert!(
        violations.is_empty(),
        "sem_ticket_endpoint_only_sealed: mascara-net must never print/log — the gathered \
         address must leave the process only inside the sealed ticket:\n{}",
        violations.join("\n")
    );

    // The CLI DOES print (it's the front-end) — so check its use of the gathered addresses
    // specifically: `local_endpoint_addrs` feeds the ticket, and no print/log statement in the
    // CLI mentions the endpoint/address data.
    let cli_src = std::fs::read_to_string(cli_dir().join("src").join("main.rs")).unwrap();
    let code = code_only(&cli_src);
    assert!(code.contains("local_endpoint_addrs"), "sweep is stale — the gathering call site moved");
    assert!(code.contains("into_file_ticket"), "sweep is stale — the ticket-construction call site moved");

    let mut cli_violations: Vec<String> = Vec::new();
    for (idx, raw) in code.lines().enumerate() {
        let is_print = raw.contains("println!") || raw.contains("eprintln!") || raw.contains("print!");
        if is_print && (raw.contains("endpoint") || raw.contains(".addrs")) {
            cli_violations.push(format!("  main.rs:{} — {}", idx + 1, raw.trim()));
        }
    }
    assert!(
        cli_violations.is_empty(),
        "sem_ticket_endpoint_only_sealed: the CLI prints something mentioning the endpoint/addrs:\n{}",
        cli_violations.join("\n")
    );
}

/// MAS-INV-4 — the dialer's public transfer function requires a `ConsentAck` **by value**: a
/// structural, compile-level guarantee (removing the parameter is a compile error, not a silent
/// behavior change) that no dial path from "ticket opened" to "bytes moving" can skip it.
///
/// Guards `sem_no_bytes_before_consent`'s structural half (SEMANTIC_MODEL.md, Tier B). The
/// behavioural half (the ack is constructible ONLY via `consent::acknowledge_ip_exposure`) is
/// `mascara-net/src/consent.rs`'s `ack_is_constructible_via_the_one_function` test.
/// **Covers EVERY public dialing entry point, not just `pull`** (codex #12): M3 added
/// `fetch_manifest` and `pull_folder`, each of which opens its own connection and moves bytes. A
/// sweep that checked only `pull` would stay green if either new entry point lost its ack — so the
/// list below is asserted to be exhaustive against `dialer.rs`'s public `pub async fn`s.
#[test]
fn sem_no_bytes_before_consent() {
    let dialer_src = std::fs::read_to_string(net_dir().join("src").join("dialer.rs")).unwrap();
    let code = code_only(&dialer_src);

    // Every public async fn in the dialer dials the sender and moves bytes — all must gate on a
    // ConsentAck taken BY VALUE.
    let public_fns: Vec<String> = code
        .match_indices("pub async fn ")
        .map(|(i, _)| {
            let rest = &code[i + "pub async fn ".len()..];
            let end = rest.find('(').unwrap_or(0);
            // Strip any generic parameter list (`pull_folder<P, D>` → `pull_folder`).
            let name = &rest[..end];
            name.split('<').next().unwrap_or(name).to_string()
        })
        .collect();
    assert!(
        public_fns.iter().any(|f| f == "pull")
            && public_fns.iter().any(|f| f == "fetch_manifest")
            && public_fns.iter().any(|f| f == "pull_folder"),
        "sweep is stale — expected the dialer's three byte-moving entry points \
         (pull / fetch_manifest / pull_folder), found: {public_fns:?}"
    );

    for name in &public_fns {
        let needle = format!("pub async fn {name}");
        let sig_start = code.find(&needle).expect("just enumerated");
        let sig_end = code[sig_start..]
            .find(" {")
            .map(|i| sig_start + i)
            .unwrap_or_else(|| panic!("could not find the end of `{name}`'s signature"));
        let signature = &code[sig_start..sig_end];
        assert!(
            signature.contains("ConsentAck"),
            "MAS-INV-4: `dialer::{name}` dials the sender, so it must take a `ConsentAck` by \
             value — the whole mechanism lives in its signature. Got:\n{signature}"
        );
        // ...and specifically NOT `&ConsentAck`/`Option<ConsentAck>` — a reference or optional
        // value would let a caller route around ever having called `acknowledge_ip_exposure`.
        assert!(
            !signature.contains("&ConsentAck") && !signature.contains("Option<ConsentAck>"),
            "MAS-INV-4: `dialer::{name}`'s `ConsentAck` must be taken BY VALUE, not by reference \
             or as an Option:\n{signature}"
        );
    }
}

/// MAS-INV-4 — even `mascara recv --yes` prints the IP-exposure notice before proceeding: a
/// source-order sweep that the `println!(...IP_EXPOSURE_NOTICE...)` call is NOT nested inside the
/// `if !yes` confirmation block (i.e., it runs unconditionally), so `--yes` cannot silently skip
/// the disclosure.
///
/// Guards `sem_consent_notice_always_printed` (SEMANTIC_MODEL.md, Tier B). Behavioural companion:
/// `mascara-net/src/consent.rs`'s `notice_states_the_real_property_honestly` test pins the text
/// itself (`sem_consent_copy_binding_tier`).
#[test]
fn sem_consent_notice_always_printed() {
    let cli_src = std::fs::read_to_string(cli_dir().join("src").join("main.rs")).unwrap();
    let code = code_only(&cli_src);

    let notice_line = code
        .lines()
        .position(|l| l.contains("IP_EXPOSURE_NOTICE"))
        .unwrap_or_else(|| panic!("sweep is stale — no reference to IP_EXPOSURE_NOTICE in the CLI"));
    // M3: the notice + prompt moved into `consent_prompt`, whose skip branch is `if yes { return
    // Ok(true) }` — accept either polarity; the property is the ORDER, not the spelling.
    let yes_check_line = code
        .lines()
        .position(|l| l.contains("if !yes") || l.contains("if yes"))
        .unwrap_or_else(|| panic!("sweep is stale — no `--yes` branch found in the CLI consent path"));

    assert!(
        notice_line < yes_check_line,
        "MAS-INV-4: the IP-exposure notice must print BEFORE the `--yes`/prompt branch, so --yes \
         can only skip the PROMPT, never the disclosure (notice at line {}, `if !yes` at line {})",
        notice_line + 1,
        yes_check_line + 1
    );

    // Stage 2 of a FOLDER receive opens a second connection (DESIGN §5, amended 2026-07-27 —
    // codex #5). It carries the short `IP_EXPOSURE_REMINDER` rather than repeating the full
    // notice (same sharer, nothing new disclosed), but that reminder is subject to the SAME
    // rule: printed before the `--yes` branch, so a scripted folder pull is never silent at the
    // moment the second connection opens.
    let reminder_line = code
        .lines()
        .position(|l| l.contains("IP_EXPOSURE_REMINDER"))
        .unwrap_or_else(|| {
            panic!(
                "sweep is stale — no reference to IP_EXPOSURE_REMINDER in the CLI. Folder stage 2 \
                 must disclose that it opens a second connection (DESIGN §5)."
            )
        });
    // The `--yes` branch INSIDE `start_prompt` — the first one at or after the reminder print.
    let start_yes_line = code
        .lines()
        .enumerate()
        .skip(reminder_line)
        .find(|(_, l)| l.contains("if yes") || l.contains("if !yes"))
        .map(|(i, _)| i)
        .unwrap_or_else(|| panic!("sweep is stale — no `--yes` branch after the stage-2 reminder"));
    assert!(
        reminder_line < start_yes_line,
        "MAS-INV-4: the folder stage-2 reminder must print BEFORE its `--yes` branch (reminder at \
         line {}, branch at line {})",
        reminder_line + 1,
        start_yes_line + 1
    );
}
