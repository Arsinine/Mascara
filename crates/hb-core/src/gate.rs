//! The iroh file-transfer auth gate — H2/H17's *pure* trust logic (spec §File Sharing &
//! Transfer threat model).
//!
//! L3 (`hb-p2p-it`, real iroh + QUIC) is **not** in CI, so the security-critical decisions are
//! pulled here, next to `binding`, as pure functions with adversarial L1 coverage — the gate's
//! only CI safety net. `transfer.rs` (in hb-app) is the *caller*: it reads the wire frame, then
//! defers every trust decision to these functions.
//!
//!   - **H17 (server / sharer):** the requester presents an `npub`-signed [`Token`] at handshake
//!     (an assertion over their iroh node key + a fresh timestamp). The server
//!     [`verify_binding_token`]s it, matches [`Token::node_key`] to `conn.remote_id()`, and gates
//!     `require_follow` on the extracted npub via [`follower_gate`].
//!   - **H2 (client / downloader):** resolves the peer's node key from their *verified presence
//!     binding* (`binding::resolve_node_key`), never from a relay-supplied address.
//!
//! The token is **ephemeral** (TTL = the verifier's `max_age`, never stored on a relay), so it
//! carries only a forward-compat version byte — no backward-tolerance machinery. Replay within
//! the freshness window is an accepted risk (QUIC channel encryption + the node-key match defeat
//! cross-connection replay; an in-connection re-present is benign), so there is no nonce.

use std::time::Duration;

use nostr::prelude::*;

use crate::error::HbError;
use crate::identity::{verify_event, Identity};
use crate::tag_util::{tag_u8, tag_val, TagU8};

/// XFER binding-token kind. Ephemeral (20000–29999 → relays don't store it), distinct from
/// NIP-98 (27235).
pub const KIND_XFER_TOKEN: u16 = 27_492;

/// Forward-compat version byte for the binding token. A token-format change is a forced
/// server-side bump (the token is ephemeral, so there is no backward tolerance to maintain).
pub const TOKEN_V: u8 = 1;

/// Tolerated clock skew for a future-dated token (matches the presence-binding ±300 s window).
const FUTURE_SKEW_SECS: u64 = 300;

/// Hard cap on the declared length of the pre-auth token frame (Mission §5 / AB7). Checked
/// *before* any allocation so a hostile length-prefix can't drive a pre-auth OOM.
pub const MAX_TOKEN_FRAME_BYTES: usize = 8 * 1024;

/// Hard cap on the declared length of the xfer request frame (the existing 64 KiB request cap).
pub const MAX_XFER_REQUEST_BYTES: usize = 64 * 1024;

const TAG_NODE: &str = "hb-node"; // bound iroh Ed25519 node key, hex
const TAG_TOKEN_VERSION: &str = "hb-tcv"; // token version byte

/// An `npub`-signed binding token (H17): an authorization assertion over the requester's iroh
/// node key + a fresh timestamp, presented as the first length-prefixed frame on the XFER stream.
/// Modelled as a signed NIP-01 event so it reuses the audited Schnorr sign/verify path.
#[derive(Debug, Clone)]
pub struct Token(Event);

impl Token {
    /// The canonical wire bytes for the length-prefixed XFER frame.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_json().into_bytes()
    }

    /// Parse a token from wire bytes. Garbage / malformed JSON returns a reasoned `Err`, never a
    /// panic — the verification (signature, kind, freshness) still happens in
    /// [`verify_binding_token`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HbError> {
        let event = Event::from_json(bytes)
            .map_err(|e| HbError::InvalidEvent(format!("malformed binding token: {e}")))?;
        Ok(Token(event))
    }

    /// The bound iroh node key, hex-decoded from the (signed) `hb-node` tag. Only trustworthy
    /// **after** [`verify_binding_token`] succeeds — the tag is then authenticated by the npub.
    pub fn node_key(&self) -> Result<[u8; 32], HbError> {
        let hex_s = tag_val(&self.0, TAG_NODE)
            .ok_or_else(|| HbError::InvalidEvent("binding token missing node tag".into()))?;
        ::hex::decode(&hex_s)
            .map_err(|_| HbError::InvalidEvent("token node key is not valid hex".into()))?
            .try_into()
            .map_err(|_| HbError::InvalidEvent("token node key is not 32 bytes".into()))
    }

    /// The claimed signer (only trustworthy after verification).
    pub fn npub(&self) -> PublicKey {
        self.0.pubkey
    }
}

/// Build an `npub`-signed binding token over `node_key`, stamped `now` (H17).
pub fn build_binding_token(
    identity: &Identity,
    node_key: &[u8; 32],
    now: u64,
) -> Result<Token, HbError> {
    let event = identity.sign(
        EventBuilder::new(Kind::from_u16(KIND_XFER_TOKEN), "")
            .tags([
                Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(node_key)]),
                Tag::custom(TagKind::custom(TAG_TOKEN_VERSION), [TOKEN_V.to_string()]),
            ])
            .custom_created_at(Timestamp::from(now)),
    )?;
    Ok(Token(event))
}

/// Verify a binding token as of `now`, accepting it only within `max_age` of its timestamp.
/// Returns the requester's **npub** (the value `require_follow` gates on); the bound node key is
/// read via [`Token::node_key`] and matched to `conn.remote_id()` by the caller.
///
/// Rejects, each with a reason: a bad/forged signature, the wrong kind, an unknown version, a
/// stale token (older than `max_age`), and a future-dated token (beyond the ±300 s skew — the
/// guard against an `abs(now - ts)` impl that would admit a far-future token).
pub fn verify_binding_token(
    token: &Token,
    now: u64,
    max_age: Duration,
) -> Result<PublicKey, HbError> {
    let event = &token.0;
    // Schnorr signature + canonical id: the npub signed exactly this node key + timestamp.
    verify_event(event)?;
    if event.kind != Kind::from_u16(KIND_XFER_TOKEN) {
        return Err(HbError::InvalidEvent(format!(
            "expected xfer-token kind {KIND_XFER_TOKEN}, got {}",
            event.kind.as_u16()
        )));
    }
    // Version byte recognised (forward-compat signalling).
    let v = match tag_u8(event, TAG_TOKEN_VERSION) {
        TagU8::Value(v) => v,
        TagU8::Missing => return Err(HbError::InvalidEvent("binding token missing version".into())),
        TagU8::Malformed(s) => {
            return Err(HbError::InvalidEvent(format!("binding token malformed version: {s}")))
        }
    };
    if v == 0 || v > TOKEN_V {
        return Err(HbError::UnsupportedVersion(v));
    }
    // Freshness — explicit window. Future-dated beyond the skew is rejected separately from stale,
    // so a far-future timestamp can't slip through an absolute-difference check.
    let created = event.created_at.as_u64();
    if created > now.saturating_add(FUTURE_SKEW_SECS) {
        return Err(HbError::BindingNotYetValid);
    }
    if now > created.saturating_add(max_age.as_secs()) {
        return Err(HbError::BindingExpired);
    }
    Ok(event.pubkey)
}

/// The H17 follower gate (pure). Admits the request when `require_follow` is off, or when the
/// requester's npub is in `followers`; otherwise rejects with the "restricted to followers" wire
/// string. The gate keys on **npub**, never a per-node transport id.
pub fn follower_gate(
    require_follow: bool,
    followers: &[PublicKey],
    requester: &PublicKey,
) -> Result<(), HbError> {
    if !require_follow || followers.contains(requester) {
        Ok(())
    } else {
        Err(HbError::RestrictedToFollowers)
    }
}

/// Reject an xfer request frame whose declared length exceeds the 64 KiB cap (AB7).
pub fn check_request_len(declared: usize) -> Result<(), HbError> {
    if declared > MAX_XFER_REQUEST_BYTES {
        Err(HbError::RequestTooLarge { declared, max: MAX_XFER_REQUEST_BYTES })
    } else {
        Ok(())
    }
}

/// Reject a pre-auth token frame whose declared length exceeds [`MAX_TOKEN_FRAME_BYTES`]
/// (Mission §5 / AB7) — checked *before* any allocation.
pub fn check_token_frame_len(declared: usize) -> Result<(), HbError> {
    if declared > MAX_TOKEN_FRAME_BYTES {
        Err(HbError::TokenFrameTooLarge { declared, max: MAX_TOKEN_FRAME_BYTES })
    } else {
        Ok(())
    }
}

/// The per-npub concurrent-download predicate (AB7). `current` is the slot count *after*
/// acquiring; admitted only while it stays within `limit` (`None` = unlimited).
pub fn check_download_limit(current: u32, limit: Option<u32>) -> Result<(), HbError> {
    match limit {
        Some(max) if current > max => Err(HbError::DownloadLimitReached),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_AGE: Duration = Duration::from_secs(300);

    fn node() -> [u8; 32] {
        rand::random()
    }

    #[test]
    fn token_signed_by_npub_over_node_key_verifies() {
        let id = Identity::generate();
        let nk = node();
        let now = 1_700_000_000u64;
        let token = build_binding_token(&id, &nk, now).unwrap();
        let npub = verify_binding_token(&token, now, MAX_AGE).unwrap();
        assert_eq!(npub, id.public_key(), "verify returns the requester's npub");
        assert_eq!(token.node_key().unwrap(), nk, "the bound node key is recoverable + authenticated");
    }

    #[test]
    fn token_for_a_different_node_key_rejected() {
        // The server matches the (authenticated) bound node key to conn.remote_id(); a token
        // minted for node A does not authorise a connection from node B.
        let id = Identity::generate();
        let node_a = node();
        let node_b = node();
        let now = 1_700_000_000u64;
        let token = build_binding_token(&id, &node_a, now).unwrap();
        verify_binding_token(&token, now, MAX_AGE).unwrap();
        assert_ne!(token.node_key().unwrap(), node_b, "bound node key must not match a different remote id");
    }

    #[test]
    fn token_signed_by_wrong_npub_rejected() {
        // AB4: a token whose pubkey is swapped to another identity (claiming to be them) fails the
        // signature check — the wrong-signer gate.
        let id = Identity::generate();
        let other = Identity::generate();
        let now = 1_700_000_000u64;
        let good = build_binding_token(&id, &node(), now).unwrap();
        let forged = Token(Event::new(
            good.0.id,
            other.public_key(), // claim to be `other`
            good.0.created_at,
            good.0.kind,
            good.0.tags.clone(),
            "",
            good.0.sig,
        ));
        assert!(matches!(
            verify_binding_token(&forged, now, MAX_AGE),
            Err(HbError::InvalidSignature)
        ));
    }

    #[test]
    fn stale_token_rejected_outside_freshness_window() {
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        // Stamped max_age + 1s in the past → stale.
        let token = build_binding_token(&id, &node(), now - (MAX_AGE.as_secs() + 1)).unwrap();
        assert!(matches!(verify_binding_token(&token, now, MAX_AGE), Err(HbError::BindingExpired)));
    }

    #[test]
    fn future_dated_token_rejected_beyond_clock_skew() {
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        // Stamped beyond the +300 s skew → rejected as not-yet-valid (not silently accepted).
        let token = build_binding_token(&id, &node(), now + FUTURE_SKEW_SECS + 60).unwrap();
        assert!(matches!(
            verify_binding_token(&token, now, MAX_AGE),
            Err(HbError::BindingNotYetValid)
        ));
    }

    #[test]
    fn token_within_clock_skew_window_accepted() {
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        // A token a little ahead of our clock (within skew) and one slightly in the past both pass.
        let ahead = build_binding_token(&id, &node(), now + FUTURE_SKEW_SECS - 10).unwrap();
        assert!(verify_binding_token(&ahead, now, MAX_AGE).is_ok());
        let recent = build_binding_token(&id, &node(), now - 30).unwrap();
        assert!(verify_binding_token(&recent, now, MAX_AGE).is_ok());
    }

    #[test]
    fn malformed_token_rejected_not_panicked() {
        // Garbage bytes never panic — they fail to parse with a reason.
        assert!(Token::from_bytes(b"not json at all").is_err());
        assert!(Token::from_bytes(b"{}").is_err());
        // A well-formed event of the wrong kind is rejected on the kind pin.
        let id = Identity::generate();
        let now = 1_700_000_000u64;
        let wrong_kind = Token(
            id.sign(
                EventBuilder::new(Kind::TextNote, "")
                    .tags([
                        Tag::custom(TagKind::custom(TAG_NODE), [hex::encode(node())]),
                        Tag::custom(TagKind::custom(TAG_TOKEN_VERSION), [TOKEN_V.to_string()]),
                    ])
                    .custom_created_at(Timestamp::from(now)),
            )
            .unwrap(),
        );
        assert!(matches!(
            verify_binding_token(&wrong_kind, now, MAX_AGE),
            Err(HbError::InvalidEvent(_))
        ));
    }

    #[test]
    fn token_roundtrips_through_wire_bytes() {
        let id = Identity::generate();
        let nk = node();
        let now = 1_700_000_000u64;
        let token = build_binding_token(&id, &nk, now).unwrap();
        let bytes = token.to_bytes();
        let back = Token::from_bytes(&bytes).unwrap();
        assert_eq!(verify_binding_token(&back, now, MAX_AGE).unwrap(), id.public_key());
        assert_eq!(back.node_key().unwrap(), nk);
    }

    // ── follower gate ─────────────────────────────────────────────────────────

    #[test]
    fn bound_npub_in_follower_list_admitted() {
        let a = Identity::generate().public_key();
        let b = Identity::generate().public_key();
        assert!(follower_gate(true, &[a, b], &a).is_ok());
    }

    #[test]
    fn bound_npub_not_followed_rejected_with_restricted_to_followers() {
        let a = Identity::generate().public_key();
        let stranger = Identity::generate().public_key();
        let err = follower_gate(true, &[a], &stranger).unwrap_err();
        assert!(
            err.to_string().contains("restricted to followers"),
            "the denial must carry the wire string; got: {err}"
        );
    }

    #[test]
    fn require_follow_off_admits_any_valid_binding() {
        let stranger = Identity::generate().public_key();
        // require_follow off → admitted regardless of the (empty) follower list. Gate keys on npub.
        assert!(follower_gate(false, &[], &stranger).is_ok());
    }

    // ── resource caps ─────────────────────────────────────────────────────────

    #[test]
    fn request_over_size_limit_rejected() {
        assert!(check_request_len(MAX_XFER_REQUEST_BYTES).is_ok());
        assert!(matches!(
            check_request_len(MAX_XFER_REQUEST_BYTES + 1),
            Err(HbError::RequestTooLarge { .. })
        ));
    }

    #[test]
    fn oversize_token_frame_length_rejected() {
        assert!(check_token_frame_len(MAX_TOKEN_FRAME_BYTES).is_ok());
        assert!(matches!(
            check_token_frame_len(MAX_TOKEN_FRAME_BYTES + 1),
            Err(HbError::TokenFrameTooLarge { .. })
        ));
    }

    #[test]
    fn per_npub_over_download_limit_rejected() {
        assert!(check_download_limit(3, Some(3)).is_ok(), "at the limit is allowed");
        assert!(matches!(check_download_limit(4, Some(3)), Err(HbError::DownloadLimitReached)));
        assert!(check_download_limit(1_000_000, None).is_ok(), "no limit → always allowed");
    }
}
