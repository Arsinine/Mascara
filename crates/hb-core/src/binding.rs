//! The `npub` → iroh-node binding, carried in the presence event (spec §P2P Layer,
//! §File Sharing — H2/H17). *"npub X authorises iroh node Y, valid until T."*
//!
//! Modelled as a signed presence event (`KIND_PRESENCE`) whose tags carry the iroh node
//! key (a raw 32-byte Ed25519 `EndpointId` — hb-core stays transport-agnostic; hb-app maps
//! it to `iroh::EndpointId`), the **sealed** transport addresses, a schema version, and an
//! explicit `expires_at`. Because NIP-01 signs a hash over all of these, the Schnorr
//! signature covers the node key *and* the validity window. `verify_binding` additionally
//! pins the author to the **expected** `npub`, so a lying relay cannot substitute a
//! valid-but-different identity's binding.
//!
//! **M4 — the address seal.** The advertised node address *is* an IP/endpoint, so it is no
//! longer a plaintext tag: it is encrypted under the **browse-key** with the *same* primitive
//! listings use (`encrypt_listing` / `decrypt_listing` — NIP-44 v2 keyed by the browse-key via
//! the versioned HKDF, **not** a per-recipient ECDH). `verify_binding` returns the address
//! **opaque** ([`SealedAddr`]) — it never decrypts — so the public binding signature +
//! `expires_at` + `created_at`-freshness stay plaintext-verifiable, and only a browse-key
//! holder resolves the dialable address (via [`unseal_addrs`]). The legacy plaintext `hb-addrs`
//! tag is recognised and treated as **not dialable** (decision #5), never misparsed.

use nostr::prelude::*;

use crate::error::HbError;
use crate::identity::{verify_event, Identity};
use crate::listing::{decrypt_listing, encrypt_listing, BrowseKey};
use crate::tag_util::{tag_u64, tag_u8, tag_val, TagU64, TagU8};
use crate::version::{check_schema, CRYPTO_V, SCHEMA_V};

/// Presence + binding event kind (replaceable, 1xxxx range — newest per author wins).
pub const KIND_PRESENCE: u16 = 11_111;
/// Maximum validity window a binding may claim. Presence refreshes every ~5 min, so a day
/// is a generous backstop; a verifier refuses any binding asserting a longer window,
/// containing the blast radius of a misconfigured or mistakenly-published binding.
pub const MAX_BINDING_TTL_SECS: u64 = 24 * 60 * 60;

const TAG_NODE: &str = "hb-node"; // iroh Ed25519 endpoint key, hex
/// Legacy plaintext address seam (M2). M4 no longer *emits* it; the reader recognises it and
/// treats it as not-dialable (decision #5). Referenced only by the transition tests.
#[cfg(test)]
const TAG_ADDRS: &str = "hb-addrs";
const TAG_SEALED_ADDRS: &str = "hb-saddr"; // M4: address ciphertext, sealed under the browse-key
const TAG_CRYPTO: &str = "hb-cv"; // crypto/KDF version of the sealed address (mirrors listings)
const TAG_EXPIRES: &str = "hb-expires"; // explicit expiry, unix seconds
const TAG_SCHEMA: &str = "hb-v"; // payload schema version
/// Tolerance for a `created_at` slightly ahead of our clock (matches the ±300 s skew window).
const FUTURE_SKEW_SECS: u64 = 300;

/// The presence event's node-address, **sealed** under the browse-key (M4 decision #3/#4).
///
/// `verify_binding` returns this OPAQUE — it never decrypts — so a non-holder caller cannot dial
/// it and an old caller cannot misparse ciphertext as an address. Only a browse-key holder
/// resolves the dialable list, via [`SealedAddr::unseal`] / [`unseal_addrs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedAddr {
    /// A versioned ciphertext blob — decryptable only by a browse-key holder.
    Sealed { crypto_v: u8, ciphertext: String },
    /// No sealed address present: either none was advertised, or the event carries the legacy
    /// plaintext `hb-addrs` tag (M2), or its crypto-version tag is missing/malformed. Per
    /// decision #5 this is **never dialable** — recognised, not misparsed as ciphertext.
    Unavailable,
}

impl SealedAddr {
    /// Decrypt to the dialable address list, for a browse-key holder. An `Unavailable` address,
    /// a wrong key, a tampered blob, or an unknown crypto version all return a reasoned `Err`.
    pub fn unseal(&self, browse_key: &BrowseKey) -> Result<Vec<String>, HbError> {
        match self {
            SealedAddr::Sealed { crypto_v, ciphertext } => {
                unseal_addrs(browse_key, *crypto_v, ciphertext)
            }
            SealedAddr::Unavailable => Err(HbError::InvalidEvent(
                "no reachable address (legacy/unsealed presence event)".into(),
            )),
        }
    }

    /// Whether a sealed (potentially dialable) address is present at all.
    pub fn is_available(&self) -> bool {
        matches!(self, SealedAddr::Sealed { .. })
    }
}

/// A verified binding. The public fields (`npub`, `node_key`, `created_at`, `expires_at`) are
/// read straight from the signed event; `addr` is opaque (see [`SealedAddr`]).
#[derive(Debug, Clone)]
pub struct Binding {
    pub npub: PublicKey,
    pub node_key: [u8; 32],
    pub addr: SealedAddr,
    pub created_at: u64,
    pub expires_at: u64,
}

/// Seal an address list under the browse-key, reusing hb-core's listing-encryption core (the
/// *same* NIP-44 v2 primitive listings use, keyed by the browse-key via the versioned HKDF —
/// **not** a per-recipient ECDH; a presence event is a broadcast and the browse-key is the
/// shared symmetric key). Returns the base64 ciphertext for the presence event's `hb-saddr`
/// tag; the caller records [`CRYPTO_V`] alongside it.
pub fn seal_addrs(browse_key: &BrowseKey, addrs: &[String]) -> Result<String, HbError> {
    let json = serde_json::to_string(addrs)?;
    encrypt_listing(browse_key, &json)
}

/// Unseal an address list. `crypto_v` is the version read from the presence event's signed tag;
/// an unknown version is refused before any decryption (forward-compat), and a wrong key or a
/// tampered blob fails cleanly — never a panic.
pub fn unseal_addrs(
    browse_key: &BrowseKey,
    crypto_v: u8,
    ciphertext: &str,
) -> Result<Vec<String>, HbError> {
    let json = decrypt_listing(browse_key, crypto_v, ciphertext)?;
    Ok(serde_json::from_str(&json)?)
}

/// Build a signed presence event binding `node_key`, advertising `addrs` **sealed** under
/// `browse_key`, valid for `ttl_secs` from `now`. An empty `addrs` advertises no address (the
/// binding + freshness still publish; the peer is simply not dialable until it advertises one).
pub fn build_binding(
    identity: &Identity,
    node_key: &[u8; 32],
    addrs: &[String],
    browse_key: &BrowseKey,
    now: u64,
    ttl_secs: u64,
) -> Result<Event, HbError> {
    if ttl_secs > MAX_BINDING_TTL_SECS {
        return Err(HbError::InvalidEvent(format!(
            "binding ttl {ttl_secs}s exceeds max {MAX_BINDING_TTL_SECS}s"
        )));
    }
    let expires_at = now.saturating_add(ttl_secs);
    let mut tags = vec![
        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(node_key)]),
        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
        Tag::custom(TagKind::custom(TAG_EXPIRES), [expires_at.to_string()]),
    ];
    if !addrs.is_empty() {
        let ciphertext = seal_addrs(browse_key, addrs)?;
        tags.push(Tag::custom(TagKind::custom(TAG_SEALED_ADDRS), [ciphertext]));
        tags.push(Tag::custom(TagKind::custom(TAG_CRYPTO), [CRYPTO_V.to_string()]));
    }
    identity.sign(
        EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(now)),
    )
}

/// Read the opaque sealed address from a presence event. Infallible by design: a missing or
/// malformed address tag yields [`SealedAddr::Unavailable`] (not dialable) rather than failing
/// the whole binding, so the **public** binding + freshness verification is never affected by
/// the health of the address tag (decision #3).
fn read_sealed_addr(event: &Event) -> SealedAddr {
    match tag_val(event, TAG_SEALED_ADDRS) {
        Some(ciphertext) => match tag_u8(event, TAG_CRYPTO) {
            TagU8::Value(crypto_v) => SealedAddr::Sealed { crypto_v, ciphertext },
            // A sealed blob with no usable crypto version can't be unsealed → not dialable.
            TagU8::Missing | TagU8::Malformed(_) => SealedAddr::Unavailable,
        },
        // No sealed tag: nothing advertised, or a legacy plaintext `hb-addrs` event. Either way
        // it is not dialable (decision #5) — recognised, never misparsed as ciphertext.
        None => SealedAddr::Unavailable,
    }
}

/// Verify a presence event's binding as of `now`, pinned to the `expected` author. The returned
/// address is opaque ([`SealedAddr`]); the verification semantics (Schnorr + kind-pin +
/// author-pin + validity window + freshness) are exactly as before the seal.
pub fn verify_binding(event: &Event, expected: &PublicKey, now: u64) -> Result<Binding, HbError> {
    // (1) Schnorr signature + canonical id: the author signed exactly these tags.
    verify_event(event)?;
    // (2) Kind pin — a presence/binding event, not some other kind with confusable tags
    //     (NIP-01 clients key behaviour off kind; without this a profile event could pose
    //     as a binding).
    if event.kind != Kind::from_u16(KIND_PRESENCE) {
        return Err(HbError::InvalidEvent(format!(
            "expected presence kind {KIND_PRESENCE}, got {}",
            event.kind.as_u16()
        )));
    }
    // (3) Author pin — the true wrong-signer gate. A *valid* binding from a different
    //     identity is rejected (H2: a relay can't redirect to a vouched-by-someone-else node).
    if &event.pubkey != expected {
        return Err(HbError::WrongSigner);
    }
    // (4) Schema version recognised (forward-compat).
    let schema = tag_val(event, TAG_SCHEMA)
        .and_then(|s| s.parse::<u8>().ok())
        .ok_or_else(|| HbError::InvalidEvent("missing or malformed schema version".into()))?;
    check_schema(schema)?;
    // (5) Validity window — explicit expiry, bounded so a misconfigured caller can't mint a
    //     binding that lives for years.
    let created = event.created_at.as_u64();
    if created > now.saturating_add(FUTURE_SKEW_SECS) {
        return Err(HbError::BindingNotYetValid);
    }
    let expires_at = match tag_u64(event, TAG_EXPIRES) {
        TagU64::Value(v) => v,
        TagU64::Missing => return Err(HbError::InvalidEvent("missing expires_at".into())),
        TagU64::Malformed(s) => {
            return Err(HbError::InvalidEvent(format!("malformed expires_at: {s}")))
        }
    };
    if expires_at.saturating_sub(created) > MAX_BINDING_TTL_SECS {
        return Err(HbError::InvalidEvent("binding validity window exceeds the maximum".into()));
    }
    if now > expires_at {
        return Err(HbError::BindingExpired);
    }
    // (6) The bound node key.
    let node_hex =
        tag_val(event, TAG_NODE).ok_or_else(|| HbError::InvalidEvent("missing node tag".into()))?;
    let node_key: [u8; 32] = ::hex::decode(&node_hex)
        .map_err(|_| HbError::InvalidEvent("node key is not valid hex".into()))?
        .try_into()
        .map_err(|_| HbError::InvalidEvent("node key is not 32 bytes".into()))?;

    Ok(Binding {
        npub: event.pubkey,
        node_key,
        addr: read_sealed_addr(event),
        created_at: created,
        expires_at,
    })
}

/// Resolve the dialable iroh node key for `expected` from their presence event — H2's pure half.
///
/// The node key is returned **only** if the binding verifies (Schnorr + kind-pin + author-pin +
/// validity window): a presence whose binding doesn't vouch for `expected` (wrong signer, forged,
/// or expired) yields no node key, so a lying relay can't redirect a download to an impostor. The
/// QUIC *refuse-before-dial* is the caller's job (`transfer.rs`); this is the trust decision,
/// pulled to a pure, CI-tested function.
pub fn resolve_node_key(
    presence: &Event,
    expected: &PublicKey,
    now: u64,
) -> Result<[u8; 32], HbError> {
    Ok(verify_binding(presence, expected, now)?.node_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: u64 = 30 * 60;

    fn node() -> [u8; 32] {
        rand::random()
    }

    fn bk() -> BrowseKey {
        rand::random()
    }

    /// A fresh sealed presence event: (identity, node key, browse key, event, now).
    fn fresh() -> (Identity, [u8; 32], BrowseKey, Event, u64) {
        let id = Identity::generate();
        let nk = node();
        let key = bk();
        let now = 1_700_000_000u64;
        let ev =
            build_binding(&id, &nk, &["addr-a".into(), "addr-b".into()], &key, now, TTL).unwrap();
        (id, nk, key, ev, now)
    }

    #[test]
    fn valid_binding_recovers_node_key() {
        let (id, nk, key, ev, now) = fresh();
        let b = verify_binding(&ev, &id.public_key(), now).unwrap();
        assert_eq!(b.node_key, nk);
        assert_eq!(b.npub, id.public_key());
        // The address is opaque until a browse-key holder unseals it.
        assert!(b.addr.is_available(), "a built binding advertises a sealed address");
        assert_eq!(b.addr.unseal(&key).unwrap(), vec!["addr-a".to_string(), "addr-b".to_string()]);
    }

    #[test]
    fn addrs_seal_roundtrips_under_browse_key() {
        let key = bk();
        let addrs = vec!["1.2.3.4:9999".to_string(), "[::1]:443".to_string()];
        let ct = seal_addrs(&key, &addrs).unwrap();
        assert_ne!(ct, addrs.join(","), "the address must be ciphertext, not plaintext");
        assert_eq!(unseal_addrs(&key, CRYPTO_V, &ct).unwrap(), addrs);
    }

    #[test]
    fn non_holder_browse_key_cannot_unseal_addrs() {
        // A wrong browse-key (a non-holder) gets a reasoned decrypt failure, never a panic and
        // never a plaintext address.
        let (_id, _nk, _key, ev, now) = fresh();
        let b = verify_binding(&ev, &_id.public_key(), now).unwrap();
        let wrong = bk();
        assert!(matches!(b.addr.unseal(&wrong), Err(HbError::DecryptionFailed)));
    }

    #[test]
    fn public_binding_and_freshness_unchanged_by_seal() {
        // Decision #3: a sealed-address event and a (legacy) plaintext-address event with the
        // SAME public fields verify identically — same npub/node/created/expires, same freshness
        // — only the address resolution differs (sealed → dialable for a holder; plaintext →
        // not dialable).
        let id = Identity::generate();
        let nk = node();
        let key = bk();
        let now = 1_700_000_000u64;

        let sealed = build_binding(&id, &nk, &["addr".into()], &key, now, TTL).unwrap();
        // A hand-built legacy event: same node/schema/expires, but the OLD plaintext hb-addrs tag.
        let plaintext = id
            .sign(
                EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(nk)]),
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(TagKind::custom(TAG_EXPIRES), [(now + TTL).to_string()]),
                        Tag::custom(TagKind::custom(TAG_ADDRS), ["addr".to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();

        let bs = verify_binding(&sealed, &id.public_key(), now).unwrap();
        let bp = verify_binding(&plaintext, &id.public_key(), now).unwrap();

        assert_eq!(bs.npub, bp.npub);
        assert_eq!(bs.node_key, bp.node_key);
        assert_eq!(bs.created_at, bp.created_at);
        assert_eq!(bs.expires_at, bp.expires_at);
        // Both read freshness/expiry identically (both expire at the same instant).
        assert!(matches!(
            verify_binding(&sealed, &id.public_key(), now + TTL + 1),
            Err(HbError::BindingExpired)
        ));
        assert!(matches!(
            verify_binding(&plaintext, &id.public_key(), now + TTL + 1),
            Err(HbError::BindingExpired)
        ));
        // The only difference: the sealed addr unseals; the legacy plaintext is not dialable.
        assert!(bs.addr.is_available());
        assert!(!bp.addr.is_available());
    }

    #[test]
    fn tampered_sealed_addrs_rejected_with_reason() {
        // A relay flips a byte of the ciphertext (and re-signs, so the event id verifies). The
        // tamper must surface as a reasoned decrypt failure at unseal, never a panic.
        let id = Identity::generate();
        let key = bk();
        let now = 1_700_000_000u64;
        let mut chars: Vec<char> = seal_addrs(&key, &["addr".into()]).unwrap().chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        let ev = id
            .sign(
                EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(node())]),
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(TagKind::custom(TAG_EXPIRES), [(now + TTL).to_string()]),
                        Tag::custom(TagKind::custom(TAG_SEALED_ADDRS), [tampered]),
                        Tag::custom(TagKind::custom(TAG_CRYPTO), [CRYPTO_V.to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();
        let b = verify_binding(&ev, &id.public_key(), now).unwrap();
        assert!(
            matches!(
                b.addr.unseal(&key),
                Err(HbError::DecryptionFailed | HbError::InvalidEncryptedMessage)
            ),
            "a tampered sealed address must fail to unseal with a reason"
        );
    }

    #[test]
    fn seal_honours_crypto_version_discriminant() {
        // A bumped crypto version is a clean reject (recognised, refused before decrypt), never a
        // silent misparse under the wrong key.
        let key = bk();
        let ct = seal_addrs(&key, &["addr".into()]).unwrap();
        assert!(matches!(
            unseal_addrs(&key, CRYPTO_V + 1, &ct),
            Err(HbError::UnsupportedVersion(v)) if v == CRYPTO_V + 1
        ));
    }

    #[test]
    fn plaintext_or_wrong_version_addr_is_not_dialable() {
        // Decision #5, the version boundary — the ONLY CI-time guard, since L3 isn't in CI.
        let id = Identity::generate();
        let nk = node();
        let key = bk();
        let now = 1_700_000_000u64;

        // (a) A legacy plaintext hb-addrs event: verifies, but resolves to "no reachable address".
        let legacy = id
            .sign(
                EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(nk)]),
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(TagKind::custom(TAG_EXPIRES), [(now + TTL).to_string()]),
                        Tag::custom(TagKind::custom(TAG_ADDRS), ["1.2.3.4:9999".to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();
        let bl = verify_binding(&legacy, &id.public_key(), now).unwrap();
        assert!(!bl.addr.is_available(), "legacy plaintext addr must not be dialable");
        assert!(bl.addr.unseal(&key).is_err(), "legacy plaintext addr must not unseal");

        // (b) A sealed event whose crypto version is a future version: verifies, captures the
        //     version opaquely, but does not unseal under the current code (recognised, refused).
        let future = id
            .sign(
                EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(nk)]),
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(TagKind::custom(TAG_EXPIRES), [(now + TTL).to_string()]),
                        Tag::custom(
                            TagKind::custom(TAG_SEALED_ADDRS),
                            [seal_addrs(&key, &["addr".into()]).unwrap()],
                        ),
                        Tag::custom(TagKind::custom(TAG_CRYPTO), [(CRYPTO_V + 1).to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();
        let bf = verify_binding(&future, &id.public_key(), now).unwrap();
        assert!(
            matches!(bf.addr.unseal(&key), Err(HbError::UnsupportedVersion(v)) if v == CRYPTO_V + 1),
            "a wrong-version sealed addr is recognised and refused, never dialed"
        );
    }

    #[test]
    fn binding_by_wrong_npub_rejected() {
        // ID3/AB4: a *validly-signed* binding authored by B is rejected when we expect A.
        let (_id, _nk, _key, ev, now) = fresh();
        let other = Identity::generate();
        assert!(matches!(verify_binding(&ev, &other.public_key(), now), Err(HbError::WrongSigner)));
    }

    #[test]
    fn node_key_resolves_only_from_a_vouching_binding() {
        // H2 pure half: resolve yields the node key for the vouching npub, but no node key for a
        // presence event that doesn't vouch for the expected identity.
        let (id, nk, _key, ev, now) = fresh();
        assert_eq!(resolve_node_key(&ev, &id.public_key(), now).unwrap(), nk);
        let other = Identity::generate();
        assert!(matches!(
            resolve_node_key(&ev, &other.public_key(), now),
            Err(HbError::WrongSigner)
        ));
    }

    #[test]
    fn node_key_resolve_fails_for_expired_binding() {
        // A validly-signed but EXPIRED binding is rejected before dial — distinct from a forged one.
        let (id, _nk, _key, ev, now) = fresh();
        assert!(matches!(
            resolve_node_key(&ev, &id.public_key(), now + TTL + 1),
            Err(HbError::BindingExpired)
        ));
    }

    #[test]
    fn swapped_node_key_rejected() {
        // A relay swaps the node tag but reuses the signature → id mismatch → rejected.
        let (id, _nk, _key, ev, now) = fresh();
        let impostor = node();
        let forged = Event::new(
            ev.id,
            id.public_key(),
            ev.created_at,
            Kind::from_u16(KIND_PRESENCE),
            [
                Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(impostor)]),
                Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                Tag::custom(TagKind::custom(TAG_EXPIRES), [(now + TTL).to_string()]),
            ],
            "",
            ev.sig,
        );
        assert!(verify_binding(&forged, &id.public_key(), now).is_err());
    }

    #[test]
    fn expired_binding_rejected() {
        let (id, _nk, _key, ev, now) = fresh();
        assert!(matches!(
            verify_binding(&ev, &id.public_key(), now + TTL + 1),
            Err(HbError::BindingExpired)
        ));
    }

    #[test]
    fn future_dated_binding_rejected() {
        let (id, _nk, _key, ev, now) = fresh();
        let before = now.saturating_sub(FUTURE_SKEW_SECS + 60);
        assert!(matches!(
            verify_binding(&ev, &id.public_key(), before),
            Err(HbError::BindingNotYetValid)
        ));
    }

    #[test]
    fn wrong_kind_rejected() {
        // A non-presence event carrying binding-shaped tags must not pass as a binding
        // (event-confusion guard).
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        let ev = id
            .sign(
                EventBuilder::new(Kind::from_u16(30_117), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(node())]),
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(TagKind::custom(TAG_EXPIRES), [(now + TTL).to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();
        assert!(matches!(verify_binding(&ev, &id.public_key(), now), Err(HbError::InvalidEvent(_))));
    }

    #[test]
    fn excessive_ttl_rejected_on_build() {
        let id = Identity::generate();
        assert!(build_binding(&id, &node(), &[], &bk(), 1_700_000_000, MAX_BINDING_TTL_SECS + 1)
            .is_err());
    }

    #[test]
    fn oversized_window_rejected_on_verify() {
        // A binding hand-built with a window beyond the max is refused even though it is
        // validly signed and unexpired.
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        let ev = id
            .sign(
                EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(node())]),
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(
                            TagKind::custom(TAG_EXPIRES),
                            [(now + MAX_BINDING_TTL_SECS + 10).to_string()],
                        ),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();
        assert!(matches!(verify_binding(&ev, &id.public_key(), now), Err(HbError::InvalidEvent(_))));
    }

    #[test]
    fn malformed_expires_rejected() {
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        let ev = id
            .sign(
                EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(node())]),
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(TagKind::custom(TAG_EXPIRES), ["soon".to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();
        assert!(matches!(verify_binding(&ev, &id.public_key(), now), Err(HbError::InvalidEvent(_))));
    }

    #[test]
    fn missing_node_tag_rejected() {
        // A presence event with no node tag is not a usable binding.
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        let ev = id
            .sign(
                EventBuilder::new(Kind::from_u16(KIND_PRESENCE), "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                        Tag::custom(TagKind::custom(TAG_EXPIRES), [(now + TTL).to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap();
        assert!(matches!(verify_binding(&ev, &id.public_key(), now), Err(HbError::InvalidEvent(_))));
    }
}
