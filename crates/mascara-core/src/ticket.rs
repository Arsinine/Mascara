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

use crate::assertion::{self, LinkAssertion};
use crate::card::Card;
use crate::error::CoreError;
use crate::identity::Identity;

/// **Body schema** version — the frozen-at-launch discriminant an opener refuses if it does not
/// recognise. Bumped to 2 at M3 stage 2 (the `payload` enum + `sender_card` + wired
/// `link_assertion`).
///
/// **Distinct from [`TICKET_PREFIX`].** The prefix names the *envelope/string format* — the
/// crypto_box sealed-box wrapper + the `mascara-ticket-v1:` recogniser — which is unchanged across
/// a body-schema bump. `TICKET_VERSION` names the *postcard body schema* the sealed box carries.
/// A body change bumps `TICKET_VERSION`; an envelope/crypto change would bump the prefix and re-
/// freeze the seal-side golden vector.
pub const TICKET_VERSION: u8 = 2;
/// The recognisable string prefix (DESIGN §3): makes a ticket identifiable without being openable
/// by anyone but the recipient. Names the **envelope/string format** (the crypto_box sealed-box
/// wrapper and this recogniser), NOT the body schema — see [`TICKET_VERSION`] for the distinction.
/// Unchanged across the v1-to-v2 body bump; a future envelope/crypto change would bump this and
/// re-freeze the seal-side golden vector.
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

/// What is moved — the derived accessor form of [`Payload`]'s discriminant. Kept as a distinct
/// enum so the CLI's reasoned refusals can say "folder transfer lands later in M3" without touching
/// the payload's variant data, and so the M2-era `Kind::Folder`-recognises-but-refuses path stays
/// intact. See [`Ticket::kind`].
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

/// FOLDER kind (M3): the folder name + the commitment to its manifest. Deliberately minimal — no
/// size/totals, no md5/mime. Per DESIGN §5 two-stage consent the folder contents/total size are
/// UNKNOWN until the manifest streams at serve time, so a folder ticket must not carry them; the
/// receiver learns them from the manifest it fetches and verifies against [`FolderRef::root_hash`]
/// (DESIGN §4: `sha256(manifest bytes) == root_hash`, checked before any path in it is trusted).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FolderRef {
    pub name: String,
    /// `sha256` of the sender's manifest postcard bytes (DESIGN §4 / chorus H4). The receiver
    /// buffers the full manifest and verifies its bytes against this before acting on a path.
    pub root_hash: [u8; 32],
}

/// What the ticket moves. A tag + the kind-specific record (postcard: varint discriminant +
/// positional record), which makes kind/ref inconsistency unrepresentable — matching the project's
/// structural-enforcement style (`ConsentAck`, history's origin-less `Completed`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Payload {
    File(FileRef),
    Folder(FolderRef),
}

/// The sender's reachability, network-agnostically (opaque to core — `mascara-net` fills it at M2).
/// Address candidates are strings so core never depends on iroh; empty at M1 (the brief).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Endpoint {
    /// Direct address candidates (LAN + public/IPv6). Empty placeholder at M1.
    pub addrs: Vec<String>,
    /// The holepunch-coordinator URL (D1/D11). `None` at M1.
    pub coordinator: Option<String>,
}

/// The transfer ticket (spec §Core Concepts).
///
/// **v2 schema (M3 stage 2).** `payload` (a [`Payload`] enum) replaces the v1 `kind`+`file_ref`
/// pair; `sender_card` replaces `endpoint_key`. The card is the sender's 129-byte
/// `Card::payload_bytes()` form (`0x01 || transport_pk || sealing_pk || binding_sig`) — the exact
/// byte sequence a `link_assertion` signs over — so the opener validates the carried card
/// (`Card::from_payload_bytes`, which verifies the H1 binding signature) and the verifier gets the
/// precise bytes the assertion signed over, with no redundant transport-pk copy to keep in sync.
/// Transport pinning stays available via [`Ticket::sender_card`]`.transport_pk`.
///
/// The optional `link_assertion` — its type and verification — lives in [`crate::assertion`], the
/// single module that touches the hoard-key mechanism (MAS-INV-1's allowed exception). A
/// present-but-invalid assertion is a hard refusal at [`Ticket::open`]; absence stays fine.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ticket {
    /// Schema version (must be [`TICKET_VERSION`]).
    pub v: u8,
    pub payload: Payload,
    pub grant: Grant,
    /// Sealed addr candidates — input to the module (net's job at M2); empty placeholder at M1.
    pub endpoint: Endpoint,
    /// The sender's contact card in its canonical payload-bytes form (`Card::payload_bytes()`,
    /// 129 bytes) — what a `link_assertion` signs over. Validated (binding-sig checked) at open.
    pub sender_card: Vec<u8>,
    pub link_assertion: Option<LinkAssertion>,
    /// OPTIONAL expiry. Default `None`: tickets persist until the sender revokes (D6).
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Per-ticket id; the sender's listener refuses a revoked nonce (M2).
    pub nonce: Nonce,
}

impl Ticket {
    /// Assemble a **file, download** ticket. `endpoint`/`sender_card`/`link_assertion` come from
    /// the caller (net at M2, synthetic in tests); the nonce is supplied by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn new_file(
        file_ref: FileRef,
        endpoint: Endpoint,
        sender_card: Vec<u8>,
        link_assertion: Option<LinkAssertion>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        nonce: Nonce,
    ) -> Self {
        Ticket {
            v: TICKET_VERSION,
            payload: Payload::File(file_ref),
            grant: Grant::Download,
            endpoint,
            sender_card,
            link_assertion,
            expires_at,
            nonce,
        }
    }

    /// Assemble a **folder, download** ticket. `root_hash` commits to the manifest bytes the
    /// receiver fetches and verifies; `endpoint`/`sender_card`/`link_assertion`/`nonce` as
    /// [`new_file`](Self::new_file).
    #[allow(clippy::too_many_arguments)]
    pub fn new_folder(
        folder_ref: FolderRef,
        endpoint: Endpoint,
        sender_card: Vec<u8>,
        link_assertion: Option<LinkAssertion>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        nonce: Nonce,
    ) -> Self {
        Ticket {
            v: TICKET_VERSION,
            payload: Payload::Folder(folder_ref),
            grant: Grant::Download,
            endpoint,
            sender_card,
            link_assertion,
            expires_at,
            nonce,
        }
    }

    /// The derived kind discriminant (File/Folder) — convenience over [`Payload`]. The CLI uses it
    /// for reasoned refusals ("folder transfer lands later in M3"); a new payload variant would
    /// grow the match here.
    pub fn kind(&self) -> Kind {
        match self.payload {
            Payload::File(_) => Kind::File,
            Payload::Folder(_) => Kind::Folder,
        }
    }

    /// The file record, if this is a file ticket. Returns `None` for a folder ticket so an M2-era
    /// file-only caller can match and give a reasoned refusal rather than touching folder data.
    pub fn file_ref(&self) -> Option<&FileRef> {
        match &self.payload {
            Payload::File(fr) => Some(fr),
            Payload::Folder(_) => None,
        }
    }

    /// The folder record, if this is a folder ticket. Returns `None` for a file ticket.
    pub fn folder_ref(&self) -> Option<&FolderRef> {
        match &self.payload {
            Payload::File(_) => None,
            Payload::Folder(fr) => Some(fr),
        }
    }

    /// The parsed+validated sender card. Called only after [`Ticket::open`] has already validated
    /// the card (so this does not re-run the binding-sig check); for an unopened/hand-built ticket
    /// a malformed `sender_card` surfaces here as an `InvalidCard` error.
    pub fn sender_card(&self) -> Result<Card, CoreError> {
        Card::from_payload_bytes(&self.sender_card)
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
    /// an unrecognised schema version, a carried `sender_card` that fails card validation (chorus
    /// H1 — a malformed or unbound card is refused), or a present-but-invalid `link_assertion`
    /// (MR-4) — recognise-and-refuse, never a panic.
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
        // Validate the carried sender card (chorus H1 + the M3 schema change): a malformed or
        // unbound card is a reasoned refusal. `from_payload_bytes` is the exact byte-sequence a
        // link_assertion signs over, so the verifier (next) gets the right message for free.
        let card = Card::from_payload_bytes(&ticket.sender_card)?;
        // Wire the optional link_assertion (DESIGN §2 / MR-4 / sem_link_invalid_is_refused): a
        // present-but-invalid assertion is a HARD refusal, never a silent accept-as-absent; an
        // absent one is fine (it's optional). The card + nonce this signs over are the carried
        // card we just validated and the ticket's own nonce.
        if let Some(assertion) = &ticket.link_assertion {
            assertion::verify_link_assertion(assertion, &card, &ticket.nonce)?;
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

    fn sample_folder_ref() -> FolderRef {
        FolderRef { name: "subs".into(), root_hash: [0x22u8; 32] }
    }

    /// A sender card whose payload bytes are valid and bound (the form a v2 ticket carries). Using a
    /// real minted identity's card — never `[3u8; 32]`-style junk, which would now fail
    /// `Card::from_payload_bytes` at open.
    fn sample_sender_card() -> Vec<u8> {
        Identity::mint().card().payload_bytes()
    }

    fn sample_file_ticket(nonce: Nonce) -> Ticket {
        // Non-empty endpoint proves the opaque field round-trips through the seal.
        let endpoint = Endpoint {
            addrs: vec!["192.0.2.10:41000".into(), "[2001:db8::1]:41000".into()],
            coordinator: Some("https://relay.example/n0".into()),
        };
        Ticket::new_file(sample_file_ref(), endpoint, sample_sender_card(), None, None, nonce)
    }

    fn sample_folder_ticket(nonce: Nonce) -> Ticket {
        let endpoint = Endpoint {
            addrs: vec!["192.0.2.10:41000".into()],
            coordinator: None,
        };
        Ticket::new_folder(sample_folder_ref(), endpoint, sample_sender_card(), None, None, nonce)
    }

    #[test]
    fn seal_open_round_trip_file() {
        let recipient = Identity::mint();
        let card = recipient.card();
        let ticket = sample_file_ticket(Nonce::mint());
        let s = ticket.seal(&card).unwrap();
        assert!(s.starts_with(TICKET_PREFIX), "got: {s}");
        let opened = Ticket::open(&s, &recipient).unwrap();
        assert_eq!(ticket, opened);
        // The derived accessors agree with the payload.
        assert_eq!(opened.kind(), Kind::File);
        assert!(opened.file_ref().is_some());
        assert!(opened.folder_ref().is_none());
        assert!(opened.sender_card().is_ok());
    }

    #[test]
    fn seal_open_round_trip_folder() {
        // The v2 schema round-trips BOTH payload variants; a folder ticket opens and its
        // `root_hash` survives.
        let recipient = Identity::mint();
        let ticket = sample_folder_ticket(Nonce::mint());
        let s = ticket.seal(&recipient.card()).unwrap();
        let opened = Ticket::open(&s, &recipient).unwrap();
        assert_eq!(ticket, opened);
        assert_eq!(opened.kind(), Kind::Folder);
        assert!(opened.folder_ref().is_some());
        assert!(opened.file_ref().is_none());
        assert_eq!(opened.folder_ref().unwrap().root_hash, [0x22u8; 32]);
    }

    #[test]
    fn only_recipient_key_opens() {
        let recipient = Identity::mint();
        let stranger = Identity::mint();
        let s = sample_file_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
        // The intended recipient opens it...
        assert!(Ticket::open(&s, &recipient).is_ok());
        // ...a different identity (wrong sealing key) gets a clean, reasoned failure.
        let err = Ticket::open(&s, &stranger).unwrap_err();
        assert!(matches!(err, CoreError::Ticket(_)), "got: {err}");
    }

    #[test]
    fn missing_prefix_rejected() {
        let recipient = Identity::mint();
        let s = sample_file_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
        let without = s.strip_prefix(TICKET_PREFIX).unwrap();
        let err = Ticket::open(without, &recipient).unwrap_err().to_string();
        assert!(err.contains("missing the"), "got: {err}");
    }

    #[test]
    fn mascara_file_carrier_round_trips() {
        // A `.mascara` file is the same string, UTF-8 — with a trailing newline as files carry.
        let recipient = Identity::mint();
        let ticket = sample_file_ticket(Nonce::mint());
        let s = ticket.seal(&recipient.card()).unwrap();
        let file_contents = format!("{s}\n");
        assert_eq!(Ticket::open(&file_contents, &recipient).unwrap(), ticket);
    }

    #[test]
    fn whitespace_around_paste_tolerated() {
        let recipient = Identity::mint();
        let ticket = sample_file_ticket(Nonce::mint());
        let s = ticket.seal(&recipient.card()).unwrap();
        let padded = format!("  \t{s}\n\n");
        assert_eq!(Ticket::open(&padded, &recipient).unwrap(), ticket);
    }

    #[test]
    fn unknown_version_recognise_and_refuse() {
        // A future schema version, sealed to the right recipient, must still be refused with a
        // version reason — recognise-and-refuse, not a silent accept or a panic.
        let recipient = Identity::mint();
        let mut ticket = sample_file_ticket(Nonce::mint());
        ticket.v = 3; // one past the current v2
        let s = ticket.seal(&recipient.card()).unwrap();
        let err = Ticket::open(&s, &recipient).unwrap_err().to_string();
        assert!(err.contains("unsupported ticket version 3"), "got: {err}");
    }

    #[test]
    fn nonce_is_128_bit_and_unique() {
        assert_eq!(Nonce::mint().as_bytes().len(), 16, "nonce must be ≥128-bit");
        let a = Nonce::mint();
        let b = Nonce::mint();
        assert_ne!(a, b, "two mints must never collide");
        assert_eq!(Nonce::from_hex(&a.to_hex()).unwrap(), a);
    }

    // `sem_ticket_body_postcard_frozen` and `sem_ticket_seal_frozen` live further down (freeze-
    // class golden vectors).

    // --- Suite MAB (adversarial): every hostile input is refused with a reason, never a panic. ---

    #[test]
    fn mab_tampered_sealed_bytes_rejected() {
        let recipient = Identity::mint();
        let s = sample_file_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
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
        let s = sample_file_ticket(Nonce::mint()).seal(&recipient.card()).unwrap();
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

    // --- v2 new surfaces: carried card validation + link_assertion wiring (MR-4 / chorus H1). ---

    #[test]
    fn malformed_sender_card_refused_at_open() {
        // A sealed ticket whose carried `sender_card` is the wrong length (or otherwise not a valid
        // card payload) must be refused at open with a card reason, never accepted.
        let recipient = Identity::mint();
        let mut ticket = sample_file_ticket(Nonce::mint());
        ticket.sender_card = vec![0u8; 10]; // junk, not a 129-byte card payload
        let s = ticket.seal(&recipient.card()).unwrap();
        let err = Ticket::open(&s, &recipient).unwrap_err();
        assert!(matches!(err, CoreError::InvalidCard(_)), "got: {err}");
    }

    #[test]
    fn unbound_sender_card_refused_at_open() {
        // The H1 guarantee, enforced at the ticket's open path: a card whose transport key didn't
        // sign its sealing key (MITM-assembled) is refused even though the sealed box opens.
        let recipient = Identity::mint();
        let alice = Identity::mint().card();
        let mallory = Identity::mint().card();
        let franken = Card {
            transport_pk: alice.transport_pk,
            sealing_pk: mallory.sealing_pk,
            binding_sig: alice.binding_sig,
        };
        let mut ticket = sample_file_ticket(Nonce::mint());
        ticket.sender_card = franken.payload_bytes();
        let s = ticket.seal(&recipient.card()).unwrap();
        let err = Ticket::open(&s, &recipient).unwrap_err().to_string();
        assert!(err.contains("not bound"), "got: {err}");
    }

    /// SEMANTIC_MODEL `sem_link_invalid_is_refused` — end-to-end (was PARTIAL; now ENFORCED on the
    /// code side). A sealed ticket carrying a present-but-INVALID assertion is REFUSED by
    /// `Ticket::open` (tampered sig; also wrong-nonce and wrong-card variants); a valid assertion
    /// opens fine; an absent assertion opens fine.
    #[test]
    fn sem_link_invalid_is_refused() {
        // The Hoardbook-stand-in mint + corrupt helpers live in assertion.rs (the MAS-INV-1-exempt
        // module) so the secp256k1/schnorr/npub symbols never appear in this file.
        use crate::assertion::{corrupt_sig_for_tests, mint_link_assertion_for_tests};

        let recipient = Identity::mint();
        let sender_card = Identity::mint().card();
        let nonce = Nonce::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();

        // A VALID assertion opens fine.
        let valid = mint_link_assertion_for_tests(&sender_card, &nonce, &[0x11u8; 32]);
        let t = Ticket::new_file(
            sample_file_ref(),
            Endpoint::default(),
            sender_card.payload_bytes(),
            Some(valid.clone()),
            None,
            nonce,
        );
        let s = t.seal(&recipient.card()).unwrap();
        assert!(Ticket::open(&s, &recipient).is_ok(), "a valid assertion must not block open");

        // Tampered sig → hard refusal.
        let mut tampered = valid.clone();
        corrupt_sig_for_tests(&mut tampered);
        let t = Ticket::new_file(
            sample_file_ref(),
            Endpoint::default(),
            sender_card.payload_bytes(),
            Some(tampered),
            None,
            nonce,
        );
        let s = t.seal(&recipient.card()).unwrap();
        let err = Ticket::open(&s, &recipient).unwrap_err();
        assert!(matches!(err, CoreError::Assertion(_)), "tampered sig must be an Assertion refusal: {err}");

        // Wrong-nonce variant: assertion signed over a different nonce.
        let other_nonce = Nonce::from_hex("ffffffffffffffffffffffffffffffff").unwrap();
        let wrong_nonce = mint_link_assertion_for_tests(&sender_card, &other_nonce, &[0x11u8; 32]);
        let t = Ticket::new_file(
            sample_file_ref(),
            Endpoint::default(),
            sender_card.payload_bytes(),
            Some(wrong_nonce),
            None,
            nonce, // ticket's real nonce differs from the one signed over
        );
        let s = t.seal(&recipient.card()).unwrap();
        let err = Ticket::open(&s, &recipient).unwrap_err();
        assert!(matches!(err, CoreError::Assertion(_)), "wrong-nonce assertion must be refused: {err}");

        // Wrong-card variant: assertion signed over a DIFFERENT sender card.
        let other_card = Identity::mint().card();
        let wrong_card = mint_link_assertion_for_tests(&other_card, &nonce, &[0x11u8; 32]);
        let t = Ticket::new_file(
            sample_file_ref(),
            Endpoint::default(),
            sender_card.payload_bytes(), // ticket's carried card
            Some(wrong_card),
            None,
            nonce,
        );
        let s = t.seal(&recipient.card()).unwrap();
        let err = Ticket::open(&s, &recipient).unwrap_err();
        assert!(matches!(err, CoreError::Assertion(_)), "wrong-card assertion must be refused: {err}");

        // Absent assertion opens fine (the optional case — absence ≠ failure).
        let t = Ticket::new_file(
            sample_file_ref(),
            Endpoint::default(),
            sender_card.payload_bytes(),
            None,
            None,
            nonce,
        );
        let s = t.seal(&recipient.card()).unwrap();
        assert!(Ticket::open(&s, &recipient).is_ok(), "an absent assertion must not block open");
    }

    /// The shared fixture for both frozen-vector tests: a fully-fixed sender + recipient so the
    /// pre-seal body bytes AND the sealed envelope are byte-reproducible. The sender (transport
    /// secret 0x5a.., sealing secret 0x01..=0x20) is the carried-card half; the recipient (transport
    /// secret 0xa5.., sealing secret 0x01..=0x20) is the seal target. Re-freezing the vectors at
    /// v2 (SEMANTIC_MODEL rule 1) fixes both — at v1 only the recipient was fixed, because the v1
    /// body carried a bare 32-byte `endpoint_key`, not a full card payload.
    fn frozen_sender_recipient() -> (Identity, Identity, Vec<u8>) {
        let sealing_sk: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let sender = Identity::from_secret_bytes(&[0x5au8; 32], &sealing_sk);
        let recipient = Identity::from_secret_bytes(&[0xa5u8; 32], &sealing_sk);
        let sender_card_bytes = sender.card().payload_bytes();
        (sender, recipient, sender_card_bytes)
    }

    /// SEMANTIC_MODEL `sem_ticket_body_postcard_frozen` (A4, appraisal 2026-07-22, freeze-class).
    /// Golden vectors over the **pre-seal postcard body bytes** — deliberately NOT the sealed
    /// envelope, so the vectors survive the M2 age→crypto_box seal swap (B4) and pin exactly what
    /// the M3 manifest `root_hash` / M7 covenant commitments will rest on: postcard's positional
    /// layout (field order, Option discriminants, enum variants) for this schema. postcard is
    /// `=`-pinned in the workspace Cargo.toml; a legitimate wire change bumps TICKET_VERSION and
    /// re-freezes these vectors in the same PR (SEMANTIC_MODEL rule 1).
    ///
    /// **Re-frozen at v2 (2026-07-23, M3 stage 2).** The v2 schema change (`payload: Payload` enum
    /// replacing `kind`+`file_ref`; `sender_card: Vec<u8>` replacing `endpoint_key: [u8; 32]`)
    /// re-freezes the body in the same change as the version bump, per rule 1. Three vectors now:
    /// the full file ticket (every Option populated), a folder ticket (the new `Payload::Folder`
    /// variant discriminant + FolderRef layout), and a minimal file ticket (every Option absent).
    /// The sender card is 129 real captured bytes from a fixed identity (`frozen_sender_recipient`).
    #[test]
    fn sem_ticket_body_postcard_frozen() {
        use chrono::TimeZone;
        let (_sender, _recipient, sender_card_bytes) = frozen_sender_recipient();

        // Vector 1 — full file ticket, every Option populated (File payload + LinkAssertion +
        // expires_at Some discriminants frozen).
        let full = Ticket {
            v: TICKET_VERSION,
            payload: Payload::File(FileRef {
                name: "Akira_1988.mkv".into(),
                size: 4096,
                sha256: [7u8; 32],
                md5: [0x11u8; 16],
                mime: Some("video/x-matroska".into()),
            }),
            grant: Grant::Download,
            endpoint: Endpoint {
                addrs: vec!["192.0.2.10:41000".into(), "[2001:db8::1]:41000".into()],
                coordinator: Some("https://relay.example/n0".into()),
            },
            sender_card: sender_card_bytes.clone(),
            // Fixture from `assertion` — naming the hoard-key field here would trip the
            // MAS-INV-1 confinement sweep (it did, on this test's first draft).
            link_assertion: Some(crate::assertion::test_fixture_link_assertion()),
            expires_at: Some(chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            nonce: Nonce::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        };
        let full_bytes = postcard::to_stdvec(&full).unwrap();
        assert_eq!(
            hex::encode(&full_bytes),
            // Captured 2026-07-23 against postcard =1.1.3 for the v2 schema (TICKET_VERSION=2).
            // Regeneration: rebuild this `full` fixture, `postcard::to_stdvec`, `hex::encode`.
            "02000e416b6972615f313938382e6d6b7680200707070707070707070707070707070707070707070707070707070707070707111111111111111111111111111111110110766964656f2f782d6d6174726f736b610002103139322e302e322e31303a3431303030135b323030313a6462383a3a315d3a3431303030011868747470733a2f2f72656c61792e6578616d706c652f6e308101010d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c7ee45b8f980d35c0d3cb399ebcf55e0cd245ec2d7ac6efa6603bc8c262338a6137c740e533f6c59a6099de91950c9221f7ed22c88405b6910c998e3d2375170401050505050505050505050505050505050505050505050505050505050505050540090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090114323032362d30312d30315430303a30303a30305a203030303130323033303430353036303730383039306130623063306430653066",
            "ticket body byte layout drifted"
        );

        // Vector 2 — folder ticket (the new Payload::Folder variant discriminant (0x01) + the
        // FolderRef { name, root_hash } positional record, frozen).
        let folder = Ticket {
            v: TICKET_VERSION,
            payload: Payload::Folder(FolderRef {
                name: "subs".into(),
                root_hash: [0x22u8; 32],
            }),
            grant: Grant::Download,
            endpoint: Endpoint::default(),
            sender_card: sender_card_bytes.clone(),
            link_assertion: None,
            expires_at: None,
            nonce: Nonce::from_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
        };
        let folder_bytes = postcard::to_stdvec(&folder).unwrap();
        assert_eq!(
            hex::encode(&folder_bytes),
            // The leading `02` = TICKET_VERSION; the `01` right after = Payload::Folder
            // discriminant (File would be `00`); then the FolderRef's name + root_hash.
            "0201047375627322222222222222222222222222222222222222222222222222222222222222220000008101010d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c7ee45b8f980d35c0d3cb399ebcf55e0cd245ec2d7ac6efa6603bc8c262338a6137c740e533f6c59a6099de91950c9221f7ed22c88405b6910c998e3d237517040000203030303130323033303430353036303730383039306130623063306430653066",
            "folder payload byte layout drifted"
        );

        // Vector 3 — minimal file ticket, every Option absent (None discriminants frozen).
        let minimal = Ticket {
            v: TICKET_VERSION,
            payload: Payload::File(FileRef {
                name: "a".into(),
                size: 1,
                sha256: [0u8; 32],
                md5: [0u8; 16],
                mime: None,
            }),
            grant: Grant::Download,
            endpoint: Endpoint::default(),
            sender_card: sender_card_bytes,
            link_assertion: None,
            expires_at: None,
            nonce: Nonce::from_hex("ffffffffffffffffffffffffffffffff").unwrap(),
        };
        let minimal_bytes = postcard::to_stdvec(&minimal).unwrap();
        assert_eq!(
            hex::encode(&minimal_bytes),
            "0200016101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008101010d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c7ee45b8f980d35c0d3cb399ebcf55e0cd245ec2d7ac6efa6603bc8c262338a6137c740e533f6c59a6099de91950c9221f7ed22c88405b6910c998e3d237517040000206666666666666666666666666666666666666666666666666666666666666666",
            "ticket body byte layout drifted"
        );

        // And the frozen bytes must still decode to the same tickets (round-trip, not just encode).
        assert_eq!(postcard::from_bytes::<Ticket>(&full_bytes).unwrap(), full);
        assert_eq!(postcard::from_bytes::<Ticket>(&folder_bytes).unwrap(), folder);
        assert_eq!(postcard::from_bytes::<Ticket>(&minimal_bytes).unwrap(), minimal);
    }

    /// SEMANTIC_MODEL `sem_ticket_seal_frozen` (B4, M2 seal swap; freeze-class). Golden vector
    /// over the **sealed envelope** — frozen on the **open side**, because sealing is
    /// non-deterministic (a fresh ephemeral key per seal, so the seal side can never byte-match).
    /// The envelope below was sealed ONCE (re-frozen 2026-07-23 at v2, crypto_box 0.9.1) to the
    /// fixed recipient and committed as a literal — the test never regenerates it. It must open to
    /// the same ticket forever: a future crypto bump that changes the sealed-box format (ephemeral
    /// pk ‖ XSalsa20-Poly1305, nonce = BLAKE2b(epk ‖ rpk)) breaks here loudly instead of silently
    /// orphaning every pasted ticket. A legitimate envelope change bumps the prefix and re-freezes
    /// this vector in the same PR (SEMANTIC_MODEL rule 1).
    ///
    /// **Re-frozen at v2 (2026-07-23, M3 stage 2).** The v2 body (`payload` enum + `sender_card`)
    /// is longer than v1, so the sealed envelope re-freezes with it; the envelope *format* (the
    /// `mascara-ticket-v1:` prefix + crypto_box sealed box) is unchanged, so the prefix did not
    /// bump — only `TICKET_VERSION` did. The opened ticket now also exercises the v2 open path's
    /// carried-card validation and the (valid, fixture) link_assertion's verify step.
    #[test]
    fn sem_ticket_seal_frozen() {
        use chrono::TimeZone;
        let (_sender, recipient, sender_card_bytes) = frozen_sender_recipient();

        const GOLDEN: &str = "mascara-ticket-v1:ecpr7fLSKVjiVhzPMuMK2OkWAKJstYUXZHebTVIpZ3fA8NIl\
             KVm9yapgiFhPARlqDNB8LShwwkmmVdNIZ6v3pWs1VJFgKPjBtzbrXM3k29CyiEMh7AQKkDzh49uUmRu0\
             TAzE02nWtKQMMn5aYJ-Ml3AAxHZLv2215qaDgCRHRGjP_-kaeGpFTaJg6jOdxcemN6ym32lyzPnOmAf6\
             gQcs2F4ysgEuxd0BWKhTGKGta-bRlVdJe7sorvpphzZ0MybRrA74CqeopATBS_c_aX4Do9s2rrsfLo9L\
             gtVXpogIgLvIyS_NvjLkNdPIGSy_7TBIwEpP1R40u9vLnFUOyimeZBC4VNAeCRqdF8kNmQxRoS9qs6SF\
             zNz82gBx2PP8VvpoEnWjKPSkYVNaqdg4hN4w46q3rFaZ9WI8964c8N2hegf8qK3Bubq53IrZM1ILLspz\
             Seu0RN_2Jq_qbX-mnG7GVW6bD_MBdQ3ZmaEJgM303q65v489eqPZwcsBt1MAFxQH_w";

        // What it must open to, forever: a full-shape file ticket. The seal vector carries NO
        // link_assertion (it pins the sealed-box envelope FORMAT, not the assertion layout — the
        // body vector does the latter with its fixture assertion; this one must OPEN cleanly).
        let expected = Ticket {
            v: TICKET_VERSION,
            payload: Payload::File(FileRef {
                name: "Akira_1988.mkv".into(),
                size: 4096,
                sha256: [7u8; 32],
                md5: [0x11u8; 16],
                mime: Some("video/x-matroska".into()),
            }),
            grant: Grant::Download,
            endpoint: Endpoint {
                addrs: vec!["192.0.2.10:41000".into(), "[2001:db8::1]:41000".into()],
                coordinator: Some("https://relay.example/n0".into()),
            },
            sender_card: sender_card_bytes,
            link_assertion: None,
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
}
