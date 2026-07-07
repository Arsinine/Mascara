//! Impersonation-resistant identity fingerprint (spec §Identity display & impersonation
//! resistance; AB4b). A deterministic word+color signature derived from an `npub`, shown beside
//! every name so two distinct keys are distinguishable at a glance even when their display names
//! collide. The petname (a local name a user binds to a key on follow) lives in the contact store;
//! this is the at-a-glance distinguisher that needs no prior contact.
//!
//! **One implementation, here in Rust** (M3 decision #7): the client and the UI must agree, so the
//! algorithm is never re-derived in TypeScript — the UI obtains a computed fingerprint over the
//! Tauri boundary, and the frontend tests pin their *rendering* to the golden vectors this module's
//! test asserts (`crates/hb-app/ui/src/lib/fingerprint_vectors.json`). Change the algorithm and the
//! golden test here goes red, forcing the fixture (and the cross-language agreement) to be updated.
//!
//! **Layering note (M3 decision #1):** this is a *display affordance*, not a Nostr protocol
//! primitive — it is never embedded in an event; it exists only to help a human tell keys apart in
//! the UI. It lives in `hb-core` for solo-dev velocity (so client + UI share one derivation);
//! candidate for extraction to an `hb-display`/`hb-app` home in M4. Do not let it justify accreting
//! other UI helpers into `hb-core`.
//!
//! **Security caveat (not a cryptographic boundary):** a short, human-comparable fingerprint is
//! *grindable* — ~36 bits here (3 words × 4 bits + a 24-bit colour), so a determined attacker could
//! mine a key whose fingerprint matches a target's in feasible time. The fingerprint is therefore a
//! usability distinguisher, **not** an anti-impersonation guarantee. The real defence is the
//! **petname bound to the exact `npub`** (see `ui/src/lib/identity-display.ts::petnameFor`, which
//! flags a name reused under a different key) — the fingerprint only makes two *un-grinded* keys
//! distinguishable at a glance. Widening `WORDS` raises the grinding cost but never closes it.

use nostr::prelude::PublicKey;

/// 16 short, visually-distinct words (4 bits of selection each). Kept deliberately small so a
/// human can compare two fingerprints at a glance.
const WORDS: [&str; 16] = [
    "amber", "basalt", "cedar", "delta", "ember", "fjord", "garnet", "harbor", "indigo", "jade",
    "kelp", "lumen", "marble", "nimbus", "onyx", "pewter",
];

/// A deterministic, at-a-glance fingerprint of an `npub`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// Three words selected from well-separated key bytes.
    pub words: Vec<String>,
    /// A `#rrggbb` swatch from three further key bytes.
    pub color_hex: String,
}

/// Derive the fingerprint of a public key. The key bytes are already uniformly distributed (a
/// secp256k1 x-only pubkey), so bytes are sampled directly — no extra hashing needed — from
/// well-spread positions to maximise sensitivity to any key difference.
pub fn fingerprint(pk: &PublicKey) -> Fingerprint {
    let b = pk.to_bytes(); // [u8; 32]
    let words = vec![
        WORDS[(b[0] % 16) as usize].to_string(),
        WORDS[(b[11] % 16) as usize].to_string(),
        WORDS[(b[23] % 16) as usize].to_string(),
    ];
    let color_hex = format!("#{:02x}{:02x}{:02x}", b[5], b[16], b[27]);
    Fingerprint { words, color_hex }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// Fixed secret keys → their expected fingerprints. **This is the golden source of truth**
    /// shared with `ui/src/lib/fingerprint_vectors.json`: if the algorithm changes, this assertion
    /// fails first, and the JSON fixture (consumed by the frontend `identity-display` vitest) must
    /// be regenerated to match — that is how the Rust derivation and the TS rendering stay agreed.
    const GOLDEN: &[(&str, [&str; 3], &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            ["jade", "fjord", "jade"],
            "#dc025b",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            ["garnet", "onyx", "harbor"],
            "#ed5cb9",
        ),
    ];

    #[test]
    fn fingerprint_is_deterministic_for_an_npub() {
        let id = Identity::generate();
        let a = fingerprint(&id.public_key());
        let b = fingerprint(&id.public_key());
        assert_eq!(a, b, "the same key must always render the same fingerprint");
    }

    #[test]
    fn fingerprint_differs_for_two_distinct_keys() {
        // Two distinct keys must not collide on *both* words and color (the at-a-glance
        // distinguisher must actually distinguish). Collision on the sampled bytes is ~2^-48.
        let a = fingerprint(&Identity::generate().public_key());
        let b = fingerprint(&Identity::generate().public_key());
        assert_ne!(a, b, "two distinct keys produced an identical fingerprint");
    }

    #[test]
    fn fingerprint_matches_golden_vectors() {
        // Pins the algorithm to the published cross-language fixture (decision #7). The values
        // below are also written to ui/src/lib/fingerprint_vectors.json for the frontend test.
        for (secret, words, color) in GOLDEN {
            let id = Identity::from_secret(secret).expect("valid secret");
            let fp = fingerprint(&id.public_key());
            assert_eq!(fp.words, words.to_vec(), "words drifted for secret {secret}");
            assert_eq!(&fp.color_hex, color, "color drifted for secret {secret}");
        }
    }
}
