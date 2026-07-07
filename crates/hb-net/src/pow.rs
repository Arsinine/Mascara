//! NIP-13 proof-of-work (spec §Relay Model — "Support NIP-13 proof-of-work on publish so
//! PoW-gated relays accept us").
//!
//! PoW is a transport-layer concern: it adds a `nonce` tag and grinds the event id to a target
//! number of leading zero bits, leaving the hb-core payload (kind, content, the signed
//! `hb-v`/`hb-cv`/`d` tags) untouched. Because mining changes the id, it must happen *before*
//! signing — so [`mine_pow`] reconstructs the builder from an already-built hb-core event,
//! applies `EventBuilder::pow`, and re-signs with the same identity. The payload is preserved
//! exactly; only a `nonce` tag is added.

use hb_core::Identity;
use nostr::prelude::*;

use crate::error::NetError;

/// Count the leading zero bits of an event id's 32 bytes (the NIP-13 difficulty metric).
/// Saturates at 255 (a 256-bit-zero id is unmineable in practice).
pub fn leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut count: u32 = 0;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros(); // u8::leading_zeros is over 8 bits → 0..=8
            break;
        }
    }
    count.min(255) as u8
}

/// The achieved PoW difficulty of an event = leading zero bits of its id.
pub fn pow_difficulty(event: &Event) -> u8 {
    leading_zero_bits(event.id.as_bytes())
}

/// Re-mine an already-built hb-core event to NIP-13 `difficulty`, re-signing with `identity`.
///
/// The kind, content, and all hb-core tags (the `d` slug, `hb-v`, `hb-cv`, node binding, …) are
/// carried over verbatim — only a `nonce` tag is added and the id ground to the target. A
/// `difficulty` of 0 is a no-op (the original event is returned unchanged).
pub fn mine_pow(identity: &Identity, event: &Event, difficulty: u8) -> Result<Event, NetError> {
    if difficulty == 0 {
        return Ok(event.clone());
    }
    // Drop any pre-existing nonce tag so re-mining an already-mined event yields exactly one
    // (hb-core never emits one, but a caller could re-mine; `EventBuilder::pow` doesn't dedup).
    let builder = EventBuilder::new(event.kind, event.content.clone())
        .tags(event.tags.iter().filter(|t| t.kind() != TagKind::Nonce).cloned())
        .custom_created_at(event.created_at)
        .pow(difficulty);
    Ok(identity.sign(builder)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hb_core::event::{build_teaser, parse_teaser, Teaser, KIND_TEASER};

    // A small target so the grind is fast but the invariant is real.
    const TARGET: u8 = 8;

    fn teaser_event() -> (Identity, Event) {
        let id = Identity::generate();
        let teaser = Teaser {
            display_name: "miner".into(),
            bio: String::new(),
            tags: vec!["anime".into()],
            content_types: vec!["video".into()],
        };
        let ev = build_teaser(&id, &teaser).unwrap();
        (id, ev)
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(leading_zero_bits(&[0x0f, 0xff]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
    }

    #[test]
    fn pow_meets_target_difficulty() {
        let (id, ev) = teaser_event();
        let mined = mine_pow(&id, &ev, TARGET).unwrap();
        assert!(
            pow_difficulty(&mined) >= TARGET,
            "mined id has {} leading zero bits, want ≥{TARGET}",
            pow_difficulty(&mined)
        );
    }

    #[test]
    fn pow_id_has_leading_zero_bits_and_committed_target() {
        let (id, ev) = teaser_event();
        let mined = mine_pow(&id, &ev, TARGET).unwrap();
        // The id itself carries the work.
        assert!(leading_zero_bits(mined.id.as_bytes()) >= TARGET);
        // NIP-13: a `nonce` tag commits the *target* difficulty (2nd value) so a verifier knows
        // the work was intentional, not luck.
        let nonce = mined
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::Nonce)
            .expect("mined event must carry a nonce tag");
        let committed: u8 = nonce.as_slice()[2].parse().unwrap();
        assert_eq!(committed, TARGET, "nonce tag must commit the target difficulty");
    }

    #[test]
    fn mine_preserves_the_hb_core_payload() {
        // PoW must not corrupt what hb-core signed: the teaser still parses, verifies, and is
        // byte-identical, and the event still verifies as the same author.
        let (id, ev) = teaser_event();
        let original = parse_teaser(&ev).unwrap();
        let mined = mine_pow(&id, &ev, TARGET).unwrap();
        assert_eq!(mined.kind, Kind::from_u16(KIND_TEASER));
        assert_eq!(mined.pubkey, id.public_key());
        assert!(mined.verify().is_ok(), "re-signed event must verify");
        assert_eq!(parse_teaser(&mined).unwrap(), original, "payload preserved through PoW");
    }

    #[test]
    fn zero_difficulty_is_a_noop() {
        let (id, ev) = teaser_event();
        let out = mine_pow(&id, &ev, 0).unwrap();
        assert_eq!(out.id, ev.id, "difficulty 0 must return the event unchanged");
    }
}
