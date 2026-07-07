# Mascara

The **courier** of the Qurator family — the app that moves files. Where **Hoardbook** (the directory)
finds people and shows what they have but **moves no files**, and **Qurator** is the club, **Mascara**
moves the file two people have *already agreed* to exchange — behind its **own identity** and an
honest, per-transfer IP-exposure consent. Full design, threat model, and invariants (MAS-INV-1…6) are
in [`MASCARA_SPEC.md`](MASCARA_SPEC.md).

> **Status: preservation scaffold (pre-refactor).** This workspace exists to preserve the *working*
> file-transfer code moved verbatim out of Hoardbook (v0.9.0 `hb-app`) when Hoardbook cut in-app
> transfer (finding **H4** / Hoardbook **INV-4**). The point of the move was to **not delete work** —
> so nothing here is rewritten yet. The transfer modules are present but not wired up; see
> `crates/mascara-transfer/src/lib.rs` for the refactor TODO. The single most important refactor:
> switch the transport identity **off** the Hoardbook `npub` onto Mascara's own key (MAS-INV-1), and
> move the reachable address out of a published presence event into a **sealed transfer ticket**
> (MAS-INV-3).

## Layout

```
MASCARA_SPEC.md                         # the spec (v0.2 — refined via requirements interview; see its Decision Log)
crates/
  mascara-transfer/
    src/                                # preserved VERBATIM, transfer-only:
      transfer.rs                       #   /hoardbook/xfer/1 protocol, H2/H17 gate, integrity check
      conn.rs                           #   connection-drain helper
      p2p_it.rs                         #   L3 geo-manual integration harness
      lib.rs                            #   scaffold + refactor TODO (modules commented out)
    from-hb-app/                        # entangled hb-app sources kept WHOLE for extraction:
      presence.rs sharing.rs            #   publish_presence(seal), request_download/cancel_download
      identity_state.rs store.rs lib.rs #   the iroh_secret 3rd key; start_iroh_endpoint/accept loop
  hb-core/                              # copied verbatim — preserved dep (gate = token, binding = seal)
  hb-net/                              # copied verbatim — preserved dep (Nostr relay client)
vendor/                                # copied (the workspace wmi patch target)
```

## Relationship to the family

**Qurator** is the club (who you know), **Hoardbook** is the phonebook (who has what, and how to reach
them — moves no files), and **Mascara** is the courier (moves the file you already agreed to move,
behind its own identity and its own honest IP-exposure consent). Three apps, three trust boundaries,
one deliberate reason: so the thing that *finds* and the thing that *moves* can never become the same
honeypot.

## License

MIT
