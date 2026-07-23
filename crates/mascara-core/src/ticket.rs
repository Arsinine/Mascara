//! The transfer ticket (spec §Core Concepts / Data Model, DESIGN.md §3): the unit that authorizes
//! one exchange. A ticket is a `serde` struct, serialized **compact-binary with postcard**, then
//! **sealed with a `crypto_box` sealed box to the recipient's X25519 sealing key** (taken from
//! their contact card, D10), and wrapped as the string `mascara-ticket-v1:<base64url(sealed
//! bytes)>`. A `.mascara` file is the same string, UTF-8 (D2).
//!
//! **Only the recipient can open it.** The sealed box seals to the recipient's X25519 key; a wrong
//! sealing key, tampered bytes, a missing prefix, or an unknown schema version are each a
//! *reasoned* refusal (recognise-and-refuse), never a panic — the paste channel is untrusted
//! (spec MT5).
//!
//! **Network-free (DESIGN §1).** M1 mints **file** tickets; the `endpoint` address candidates are
//! taken as *input* (an empty placeholder here — `mascara-net` gathers real iroh addresses at M2),
//! so the whole module is unit-testable with synthetic endpoint data. Folders (`root_hash`, streamed
//! manifest) are M3.
//!
//! **The sealed box (crypto_box 0.9, `seal` feature — B4, replaced age at M2).** libsodium's
//! `crypto_box_seal` construction: a fresh ephemeral X25519 key per seal (so sealing is
//! **non-deterministic**), nonce = BLAKE2b(ephemeral pk ‖ recipient pk), XSalsa20-Poly1305 AEAD;
//! the envelope is `ephemeral pk ‖ ciphertext ‖ MAC` — [`crypto_box::SEALBYTES`] (48 bytes) of
//! overhead over the postcard body. Mascara's raw 32-byte X25519 keys (identity/card) feed
//! `crypto_box::{PublicKey, SecretKey}::from_bytes` directly — the M1 age bech32 string bridge is
//! gone. The envelope format is frozen by the `sem_ticket_seal_frozen` open-side golden vectors
//! below, so a future crypto bump cannot silently break the wire format.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::assertion::LinkAssertion;
use crate::card::Card;
use crate::error::CoreError;
use crate::identity::Identity;

/// Schema version — the frozen-at-launch discriminant an opener refuses if it does not recognise.
pub const TICKET_VERSION: u8 = 1;
/// The recognisable string prefix (DESIGN §3): makes a ticket identifiable without being openable by
/// anyone but the recipient.
pub const TICKET_PREFIX: &str = "mascara-ticket-v1:";
/// Nonce width: 128 bits of CSPRNG (spec "≥128-bit"; DESIGN §4 "collision-safe registry keys").
pub const NONCE_LEN: usize = 16;

/// A per-ticket id: `NONCE_LEN` bytes of OS CSPRNG. Serialized as lowercase hex so `issued.json`
/// stays human-inspectable (it is an identifier, not a secret — DESIGN §4).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Mint a fresh nonce from OS randomness.
    pub fn mint() -> Self {
        let mut b = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Nonce(b)
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a nonce from its hex form (used by the CLI's `--revoke <id>` and the registry).
    pub fn from_hex(s: &str) -> Result<Self, CoreError> {
        let bytes = hex::decode(s.trim())
            .map_err(|e| CoreError::Registry(format!("bad nonce hex '{s}': {e}")))?;
        let arr: [u8; NONCE_LEN] = bytes.as_slice().try_into().map_err(|_| {
            CoreError::Registry(format!("nonce must be {NONCE_LEN} bytes, got {}", bytes.len()))
        })?;
        Ok(Nonce(arr))
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({})", self.to_hex())
    }
}

impl Serialize for Nonce {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Nonce::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// What is moved. M1 mints only `File`; `Folder` is recognised so the CLI can refuse a directory
/// with a reasoned "not yet — M3", and so the wire discriminant is frozen now (folder `root_hash`
/// streaming lands at M3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Folder,
}

/// The grant this ticket carries. M1 mints only `Download`; `Sync` (a Buddy Pairing, Phase 2) is
/// recognised so M2's listener can refuse it in Phase 1 (DESIGN §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grant {
    Download,
    Sync,
}

/// FILE kind: what is moved + its content commitment (spec Data Model). `sha256` makes the transfer
/// content-verifiable end to end; `md5` is advisory legacy-catalog interop (MR-11); `mime` is the
/// sender's *declared* type the receiver sniff-checks (MT9) — a claim, never proof.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FileRef {
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
    /// Advisory md5 for legacy-catalog interop (MR-11) — collision-broken, never a trust anchor.
    /// CARRIED from Hoardbook's `ShareDescriptor`, never computed here (MR-13).
    pub md5: [u8; 16],
    pub mime: Option<String>,
}

// No `FileRef::from_path` — Mascara computes no content commitment. The sha256/md5 are Hoardbook's,
// precomputed in its catalog and delivered via `ShareDescriptor` (MR-13; SEMANTIC_MODEL
// `sem_mascara_no_commitment_hashing`). A `FileRef` is built from those carried facts by
// `ShareDescriptor::file_ref`, never by hashing bytes at ticket-creation.

/// The sender's reachability, network-agnostically (opaque to core — `mascara-net` fills it at M2).
/// Address candidates are strings so core never depends on iroh; empty at M1 (the brief).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Endpoint {
    /// Direct address candidates (LAN + public/IPv6). Empty placeholder at M1.
    pub addrs: Vec<String>,
    /// The holepunch-coordinator URL (D1/D11). `None` at M1.
    pub coordinator: Option<String>,
}

/// The transfer ticket (spec §Core Concepts). M1 shape: file tickets, `download` grant.
///
/// The optional `link_assertion` — its type and verification — lives in [`crate::assertion`], the
/// single module that touches the hoard-key mechanism (MAS-INV-1's allowed exception).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ticket {
    /// Schema version (must be [`TICKET_VERSION`]).
    pub v: u8,
    pub kind: Kind,
    pub file_ref: FileRef,
    pub grant: Grant,
    /// Sealed addr candidates — input to the module (net's job at M2); empty placeholder at M1.
    pub endpoint: Endpoint,
    /// The sender's ed25519 transport identity to pin before connecting (the transport half of the
    /// card — D10).
    pub endpoint_key: [u8; 32],
    pub link_assertion: Option<LinkAssertion>,
    /// OPTIONAL expiry. Default `None`: tickets persist until the sender revokes (D6).
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Per-ticket id; the sender's listener refuses a revoked nonce (M2).
    pub nonce: Nonce,
}

impl Ticket {
    /// Assemble a **file, download** ticket (the M1 shape). `endpoint`/`endpoint_key` come from the
    /// caller (net at M2, synthetic in tests); the nonce is minted fresh unless supplied.
    #[allow(clippy::too_many_arguments)]
    pub fn new_file(
        file_ref: FileRef,
        endpoint: Endpoint,
        endpoint_key: [u8; 32],
        link_assertion: Option<LinkAssertion>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        nonce: Nonce,
    ) -> Self {
        Ticket {
            v: TICKET_VERSION,
            kind: Kind::File,
            file_ref,
            grant: Grant::Download,
            endpoint,
            endpoint_key,
            link_assertion,
            expires_at,
            nonce,
        }
    }

    /// Seal this ticket to a recipient's card: `postcard(body)` → crypto_box-seal to the card's
    /// sealing key → base64url → `mascara-ticket-v1:` prefix. The output is non-deterministic (a
    /// fresh ephemeral key each seal); round-trip via [`Ticket::open`], never string comparison.
    pub fn seal(&self, recipient: &Card) -> Result<String, CoreError> {
        let body = postcard::to_stdvec(self)
            .map_err(|e| CoreError::Seal(format!("could not encode ticket body: {e}")))?;
        let sealed = crypto_seal(&body, &recipient.sealing_pk).map_err(CoreError::Seal)?;
        Ok(format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(&sealed)))
    }

    /// Open a ticket string (or `.mascara` file contents) with the recipient's identity. Every
    /// failure is reasoned: missing prefix, bad base64, wrong key / tampered bytes, malformed body,
    /// or an unrecognised schema version — recognise-and-refuse, never a panic.
    pub fn open(s: &str, identity: &Identity) -> Result<Ticket, CoreError> {
        let b64 = s.trim().strip_prefix(TICKET_PREFIX).ok_or_else(|| {
            CoreError::Ticket(format!("not a Mascara ticket — missing the '{TICKET_PREFIX}' prefix"))
        })?;
        let sealed = URL_SAFE_NO_PAD
            .decode(b64.trim())
            .map_err(|e| CoreError::Ticket(format!("ticket is not valid base64url: {e}")))?;
        let secret = Zeroizing::new(identity.sealing_secret_bytes());
        let body = Zeroizing::new(crypto_open(&sealed, &secret).map_err(CoreError::Ticket)?);
        let ticket: Ticket = postcard::from_bytes(&body)
            .map_err(|e| CoreError::Ticket(format!("malformed ticket body: {e}")))?;
        if ticket.v != TICKET_VERSION {
            return Err(CoreError::Ticket(format!(
                "unsupported ticket version {} (this Mascara understands v{TICKET_VERSION})",
                ticket.v
            )));
        }
        Ok(ticket)
    }
}

// --- the crypto_box sealed box (raw X25519 keys — libsodium `crypto_box_seal` compatible) -------

/// Seal `plaintext` to a raw 32-byte X25519 public key. Non-deterministic — a fresh ephemeral key
/// per call.
fn crypto_seal(plaintext: &[u8], recipient_pk: &[u8; 32]) -> Result<Vec<u8>, String> {
    crypto_box::PublicKey::from_bytes(*recipient_pk)
        .seal(&mut rand::rngs::OsRng, plaintext)
        .map_err(|_| "sealed-box encryption failed".to_string())
}

/// Open a sealed box with a raw 32-byte X25519 secret. `crypto_box::SecretKey` zeroizes its copy
/// on drop. The AEAD reports no failure detail (by design), so the error is reason-only.
fn crypto_open(sealed: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>, String> {
    if sealed.len() < crypto_box::SEALBYTES {
        return Err(format!(
            "not a sealed ticket ({} bytes — a sealed box carries at least {})",
            sealed.len(),
            crypto_box::SEALBYTES
        ));
    }
    crypto_box::SecretKey::from_bytes(*secret)
        .unseal(sealed)
        .map_err(|_| "wrong sealing key or tampered ticket".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_file_ref() -> FileRef {
        FileRef {
            name: "Akira_1988.mkv".into(),
            size: 4096,
            sha256: [7u8; 32],
            md5: [0x11u8; 16],
            mime: Some("video/x-matroska".into()),
        }
    }

    fn sample_ticket(nonce: Nonce) -> Ticket {
        // Non-empty endpoint proves the opaque field round-trips through the seal.
        let endpoint = Endpoint {
            addrs: vec!["192.0.2.10:41000".into(), "[2001:db8::1]:41000".into()],
            coordinator: Some("https://relay.example/n0".into()),
        };
        Ticket::new_file(sample_file_ref(), endpoint, [3u8; 32], None, None, nonce)
    }

    #[test]
    fn seal_open_round_trip() {
        let recipient = Identity::mint();
        let card = recipient.card();
        let ticket = sample_ticket(Nonce::mint());
        let s = ticket.seal(&card).unwrap();
        assert!(s.starts_with(TICKET_PREFIX), "got: {s}");
        let opened = Ticket::open(&s, &recipient).unwrap();
        assert_eq!(ticket, opened);
    }

    #[test]
    fn only_recipient_key_opens() {
        let recipient = Identity::mint();
        let stranger = Identity::mint();
        let s = sample_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
        // The intended recipient opens it...
        assert!(Ticket::open(&s, &recipient).is_ok());
        // ...a different identity (wrong sealing key) gets a clean, reasoned failure.
        let err = Ticket::open(&s, &stranger).unwrap_err();
        assert!(matches!(err, CoreError::Ticket(_)), "got: {err}");
    }

    #[test]
    fn missing_prefix_rejected() {
        let recipient = Identity::mint();
        let s = sample_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
        let without = s.strip_prefix(TICKET_PREFIX).unwrap();
        let err = Ticket::open(without, &recipient).unwrap_err().to_string();
        assert!(err.contains("missing the"), "got: {err}");
    }

    #[test]
    fn mascara_file_carrier_round_trips() {
        // A `.mascara` file is the same string, UTF-8 — with a trailing newline as files carry.
        let recipient = Identity::mint();
        let ticket = sample_ticket(Nonce::mint());
        let s = ticket.seal(&recipient.card()).unwrap();
        let file_contents = format!("{s}\n");
        assert_eq!(Ticket::open(&file_contents, &recipient).unwrap(), ticket);
    }

    #[test]
    fn whitespace_around_paste_tolerated() {
        let recipient = Identity::mint();
        let ticket = sample_ticket(Nonce::mint());
        let s = ticket.seal(&recipient.card()).unwrap();
        let padded = format!("  \t{s}\n\n");
        assert_eq!(Ticket::open(&padded, &recipient).unwrap(), ticket);
    }

    #[test]
    fn unknown_version_recognise_and_refuse() {
        // A future schema version, sealed to the right recipient, must still be refused with a
        // version reason — recognise-and-refuse, not a silent accept or a panic.
        let recipient = Identity::mint();
        let mut ticket = sample_ticket(Nonce::mint());
        ticket.v = 2;
        let s = ticket.seal(&recipient.card()).unwrap();
        let err = Ticket::open(&s, &recipient).unwrap_err().to_string();
        assert!(err.contains("unsupported ticket version 2"), "got: {err}");
    }

    #[test]
    fn nonce_is_128_bit_and_unique() {
        assert_eq!(Nonce::mint().as_bytes().len(), 16, "nonce must be ≥128-bit");
        let a = Nonce::mint();
        let b = Nonce::mint();
        assert_ne!(a, b, "two mints must never collide");
        assert_eq!(Nonce::from_hex(&a.to_hex()).unwrap(), a);
    }

    /// SEMANTIC_MODEL `sem_ticket_body_postcard_frozen` (A4, appraisal 2026-07-22, freeze-class).
    /// Golden vectors over the **pre-seal postcard body bytes** — deliberately NOT the sealed
    /// envelope, so the vectors survive the M2 age→crypto_box seal swap (B4) and pin exactly what
    /// the M3 manifest `root_hash` / M7 covenant commitments will rest on: postcard's positional
    /// layout (field order, Option discriminants, enum variants) for this schema. postcard is
    /// `=`-pinned in the workspace Cargo.toml; a legitimate wire change bumps TICKET_VERSION and
    /// re-freezes these vectors in the same PR (SEMANTIC_MODEL rule 1).
    #[test]
    fn sem_ticket_body_postcard_frozen() {
        use chrono::TimeZone;

        // Vector 1 — every Option populated (Some discriminants + LinkAssertion layout frozen).
        let full = Ticket {
            v: TICKET_VERSION,
            kind: Kind::File,
            file_ref: FileRef {
                name: "Akira_1988.mkv".into(),
                size: 4096,
                sha256: [7u8; 32],
                md5: [0x11u8; 16],
                mime: Some("video/x-matroska".into()),
            },
            grant: Grant::Download,
            endpoint: Endpoint {
                addrs: vec!["192.0.2.10:41000".into(), "[2001:db8::1]:41000".into()],
                coordinator: Some("https://relay.example/n0".into()),
            },
            endpoint_key: [3u8; 32],
            // Fixture from `assertion` — naming the hoard-key field here would trip the
            // MAS-INV-1 confinement sweep (it did, on this test's first draft).
            link_assertion: Some(crate::assertion::test_fixture_link_assertion()),
            expires_at: Some(chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            nonce: Nonce::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        };
        let full_bytes = postcard::to_stdvec(&full).unwrap();
        assert_eq!(
            hex::encode(&full_bytes),
            "01000e416b6972615f313938382e6d6b7680200707070707070707070707070707070707070707\
             070707070707070707070707111111111111111111111111111111110110766964656f2f782d6d\
             6174726f736b610002103139322e302e322e31303a3431303030135b323030313a6462383a3a31\
             5d3a3431303030011868747470733a2f2f72656c61792e6578616d706c652f6e30030303030303\
             030303030303030303030303030303030303030303030303030301050505050505050505050505\
             050505050505050505050505050505050505050540090909090909090909090909090909090909\
             090909090909090909090909090909090909090909090909090909090909090909090909090909\
             090909090909090114323032362d30312d30315430303a30303a30305a20303030313032303330\
             3430353036303730383039306130623063306430653066",
            "ticket body byte layout drifted"
        );

        // Vector 2 — every Option absent (None discriminants frozen).
        let minimal = Ticket {
            v: TICKET_VERSION,
            kind: Kind::File,
            file_ref: FileRef {
                name: "a".into(),
                size: 1,
                sha256: [0u8; 32],
                md5: [0u8; 16],
                mime: None,
            },
            grant: Grant::Download,
            endpoint: Endpoint::default(),
            endpoint_key: [0u8; 32],
            link_assertion: None,
            expires_at: None,
            nonce: Nonce::from_hex("ffffffffffffffffffffffffffffffff").unwrap(),
        };
        let minimal_bytes = postcard::to_stdvec(&minimal).unwrap();
        assert_eq!(
            hex::encode(&minimal_bytes),
            "010001610100000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000002066666666666666666666666666666666666666666666666666\
             66666666666666",
            "ticket body byte layout drifted"
        );

        // And the frozen bytes must still decode to the same tickets (round-trip, not just encode).
        assert_eq!(postcard::from_bytes::<Ticket>(&full_bytes).unwrap(), full);
        assert_eq!(postcard::from_bytes::<Ticket>(&minimal_bytes).unwrap(), minimal);
    }

    /// SEMANTIC_MODEL `sem_ticket_seal_frozen` (B4, M2 seal swap; freeze-class). Golden vector
    /// over the **sealed envelope** — frozen on the **open side**, because sealing is
    /// non-deterministic (a fresh ephemeral key per seal, so the seal side can never byte-match).
    /// The envelope below was sealed ONCE (2026-07-23, crypto_box 0.9.1) to the fixed sealing
    /// secret `0x01..=0x20` and committed as a literal — the test never regenerates it. It must
    /// open to the same ticket forever: a future crypto bump that changes the sealed-box format
    /// (ephemeral pk ‖ XSalsa20-Poly1305, nonce = BLAKE2b(epk ‖ rpk)) breaks here loudly instead
    /// of silently orphaning every pasted ticket. A legitimate envelope change bumps
    /// `TICKET_VERSION` and re-freezes this vector in the same PR (SEMANTIC_MODEL rule 1).
    #[test]
    fn sem_ticket_seal_frozen() {
        use chrono::TimeZone;

        // The fixed recipient: sealing secret 0x01..=0x20. (The transport half is irrelevant to
        // opening; fixed too so the whole fixture is reproducible.)
        let sealing_sk: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let recipient = Identity::from_secret_bytes(&[0xa5u8; 32], &sealing_sk);

        const GOLDEN: &str = "mascara-ticket-v1:WlHRFZ1oDP9Fd_AH7fuy3DZy-vImrP0jAyk3Ld5NUCfCFJcD\
             4LVk0cMvLKektxA58wyniCFV5ksykAz2IAzlxSdHhX8iVxHikNYT8Icn0I13mT4QxfrB8f0o-tmekYMtxx7P\
             CQhpifPvfcK6hAt_9nVTQ2LVfrpOwAeQeOPDh6KibjoqemrDoQ2mMoMwXpF64dKdEWiLotb8o1DPntjk9VOF\
             JSy1DSJCjcrMaDOTLEyk3xTsVDyLshxODwhvoNVvUbpZLLVqafoRARJFH4HK33VfjExTwpB45sKDfI9_Zqpf\
             kLzugFyB66rg5CNVNIPfObhLsLkYPbxZV--X43AIyRhluBDBToAZj64Jysn4KfaGAXYmp-8CYCtZKfeHbR4a\
             5u7-9tP82sVz7JusTtmo2JtFQNBsh5XqoDT3BGj8BUOhYiFF2TDHq0AjpVTtAnxGltD6JdlBHhqrIIvIQe93\
             j-S-v5vf0BJUx50PKcxBP3VrbhraZe9axlSN_oD3ueQ";

        // What it must open to, forever: the same full-shape ticket the postcard-body vectors pin.
        let expected = Ticket {
            v: TICKET_VERSION,
            kind: Kind::File,
            file_ref: FileRef {
                name: "Akira_1988.mkv".into(),
                size: 4096,
                sha256: [7u8; 32],
                md5: [0x11u8; 16],
                mime: Some("video/x-matroska".into()),
            },
            grant: Grant::Download,
            endpoint: Endpoint {
                addrs: vec!["192.0.2.10:41000".into(), "[2001:db8::1]:41000".into()],
                coordinator: Some("https://relay.example/n0".into()),
            },
            endpoint_key: [3u8; 32],
            link_assertion: Some(crate::assertion::test_fixture_link_assertion()),
            expires_at: Some(chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            nonce: Nonce::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        };
        assert_eq!(
            Ticket::open(GOLDEN, &recipient).unwrap(),
            expected,
            "the frozen sealed envelope no longer opens to the frozen ticket"
        );

        // The envelope is exactly the postcard body + the sealed-box overhead (ephemeral pk + MAC).
        let sealed = URL_SAFE_NO_PAD.decode(GOLDEN.strip_prefix(TICKET_PREFIX).unwrap()).unwrap();
        assert_eq!(
            sealed.len(),
            postcard::to_stdvec(&expected).unwrap().len() + crypto_box::SEALBYTES,
            "sealed-envelope overhead drifted"
        );

        // Tampering with the frozen envelope stays a reasoned refusal, never a panic...
        let mut tampered = sealed.clone();
        let i = tampered.len() - 2;
        tampered[i] ^= 0xff;
        let s = format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(&tampered));
        assert!(matches!(Ticket::open(&s, &recipient), Err(CoreError::Ticket(_))));

        // ...and so does truncating it.
        let s = format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(&sealed[..sealed.len() / 2]));
        assert!(matches!(Ticket::open(&s, &recipient), Err(CoreError::Ticket(_))));
    }

    // --- Suite MAB (adversarial): every hostile input is refused with a reason, never a panic. ---

    #[test]
    fn mab_tampered_sealed_bytes_rejected() {
        let recipient = Identity::mint();
        let s = sample_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
        let b64 = s.strip_prefix(TICKET_PREFIX).unwrap();
        let mut sealed = URL_SAFE_NO_PAD.decode(b64).unwrap();
        // Flip a byte deep in the ciphertext/MAC region.
        let i = sealed.len() - 2;
        sealed[i] ^= 0xff;
        let tampered = format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(&sealed));
        let err = Ticket::open(&tampered, &recipient).unwrap_err();
        assert!(matches!(err, CoreError::Ticket(_)), "got: {err}");
    }

    #[test]
    fn mab_bad_base64_rejected() {
        let recipient = Identity::mint();
        let err = Ticket::open(&format!("{TICKET_PREFIX}not*valid*base64url!!"), &recipient)
            .unwrap_err()
            .to_string();
        assert!(err.contains("base64url"), "got: {err}");
    }

    #[test]
    fn mab_truncated_sealed_rejected() {
        let recipient = Identity::mint();
        let s = sample_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
        let b64 = s.strip_prefix(TICKET_PREFIX).unwrap();
        let sealed = URL_SAFE_NO_PAD.decode(b64).unwrap();
        let truncated = format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(&sealed[..sealed.len() / 2]));
        assert!(matches!(Ticket::open(&truncated, &recipient), Err(CoreError::Ticket(_))));
    }

    #[test]
    fn mab_random_and_empty_blobs_rejected() {
        let recipient = Identity::mint();
        for blob in [vec![], vec![0u8; 1], vec![0xabu8; 4096]] {
            let s = format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(&blob));
            // No panic; always a reasoned error.
            assert!(Ticket::open(&s, &recipient).is_err());
        }
    }
}
