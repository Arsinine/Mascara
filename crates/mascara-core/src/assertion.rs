//! `link_assertion` — **verify-only** (spec Identity & Trust Boundary, DESIGN.md §2).
//!
//! An optional per-transfer proof that a hoard `npub` vouches for a ticket's `endpoint_key`:
//! *"hoard-npub X authorises Mascara endpoint Y for this exchange."* It rides **inside the sealed
//! ticket** (never a public relay event — MAS-INV-1/3), so it never becomes a public `npub`→endpoint
//! map. Mascara **only verifies**; **minting is Hoardbook's job** — this module also *defines the
//! signing spec* so Hoardbook can mint one later.
//!
//! **The signature.** BIP340 Schnorr over secp256k1 by the hoard `npub` (a 32-byte x-only key). The
//! signed message is the 32-byte digest
//! `SHA-256("mascara-link-v1" || card payload bytes || nonce)` — hashing to 32 bytes first matches
//! Nostr's own discipline and fits secp256k1 0.29's fixed-width `Message`. BIP340 has no key
//! recovery, so the `npub` must be handed to the verifier — it travels next to the signature in
//! [`LinkAssertion`] (chorus FQ2).
//!
//! **The one allowed `secp256k1` use (MAS-INV-1).** This tiny verify-only dependency is the single
//! exception to the `nostr`/`npub` absence sweep. No Nostr stack, no signing, no key recovery — just
//! `verify_schnorr`.

use secp256k1::schnorr::Signature;
use secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::card::Card;
use crate::error::CoreError;
use crate::ticket::Nonce;

/// Domain-separation context for the assertion signature (versioned with the format).
pub const LINK_CONTEXT: &[u8] = b"mascara-link-v1";

/// OPTIONAL per-transfer proof that a hoard `npub` vouches for a ticket's `endpoint_key` (spec
/// Identity & Trust Boundary, DESIGN.md §2). It rides inside the sealed ticket
/// ([`crate::ticket::Ticket::link_assertion`]); Mascara only **verifies** it (below), minting is
/// Hoardbook's job. This type lives here — beside its verifier and signing spec — so the whole
/// hoard-key mechanism stays in one module (MAS-INV-1's single allowed exception).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LinkAssertion {
    /// The hoard `npub` as a 32-byte BIP340 x-only public key. It travels with the signature because
    /// BIP340 has no key recovery — the verifier must be handed the claimed key (chorus FQ2).
    pub npub: [u8; 32],
    /// The 64-byte BIP340 Schnorr signature. `Vec<u8>` (not `[u8; 64]`) because serde's derive only
    /// covers arrays up to length 32; the length is checked in [`verify_link_assertion`].
    pub sig: Vec<u8>,
}

/// Test-only fixture for tests in OTHER modules that need a populated `LinkAssertion` (e.g. the
/// ticket-body golden vectors). Lives here so the `npub` field name stays confined to this module —
/// naming it anywhere else trips the MAS-INV-1 sweep (`sem_identity_never_reuses_hoard_npub`), by
/// design. Fixed bytes: key = `[5u8; 32]`, sig = `[9u8; 64]` — frozen into the golden vectors.
#[cfg(test)]
pub(crate) fn test_fixture_link_assertion() -> LinkAssertion {
    LinkAssertion { npub: [5u8; 32], sig: vec![9u8; 64] }
}

/// The exact 32-byte message a `link_assertion` signs (and Hoardbook must sign, when it mints one):
/// `SHA-256("mascara-link-v1" || card.payload_bytes() || nonce)`.
pub fn link_message(card: &Card, nonce: &Nonce) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LINK_CONTEXT);
    h.update(card.payload_bytes());
    h.update(nonce.as_bytes());
    h.finalize().into()
}

/// Verify that `assertion.npub` really signed this `card` + `nonce`. Every failure is reasoned — a
/// wrong-length or malformed signature, an npub that is not a valid x-only key, or a signature that
/// simply does not verify (forged sig / wrong card / wrong nonce / wrong npub) — never a panic
/// (spec MT3, M1 brief Suite MAB).
pub fn verify_link_assertion(
    assertion: &LinkAssertion,
    card: &Card,
    nonce: &Nonce,
) -> Result<(), CoreError> {
    let sig = Signature::from_slice(&assertion.sig).map_err(|e| {
        CoreError::Assertion(format!(
            "signature is not a valid 64-byte BIP340 schnorr signature: {e}"
        ))
    })?;
    let npub = XOnlyPublicKey::from_slice(&assertion.npub)
        .map_err(|e| CoreError::Assertion(format!("npub is not a valid x-only public key: {e}")))?;
    let msg = Message::from_digest(link_message(card, nonce));
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&sig, &msg, &npub).map_err(|_| {
        CoreError::Assertion(
            "signature does not verify for this card + nonce + npub (forged or mismatched)".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use secp256k1::{Keypair, SecretKey};

    /// A test-only signer standing in for Hoardbook: mint a BIP340 assertion for `card` + `nonce`
    /// under the hoard secret `secret`. Deterministic (`no_aux_rand`) so tests don't need OS entropy
    /// or the `rand` feature.
    fn mint(card: &Card, nonce: &Nonce, secret: &[u8; 32]) -> LinkAssertion {
        let secp = Secp256k1::signing_only();
        let sk = SecretKey::from_slice(secret).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        let msg = Message::from_digest(link_message(card, nonce));
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        LinkAssertion { npub: xonly.serialize(), sig: sig.as_ref().to_vec() }
    }

    fn fixtures() -> (Card, Nonce, [u8; 32]) {
        (Identity::mint().card(), Nonce::mint(), [0x11u8; 32])
    }

    #[test]
    fn valid_assertion_accepted() {
        let (card, nonce, secret) = fixtures();
        let a = mint(&card, &nonce, &secret);
        assert!(verify_link_assertion(&a, &card, &nonce).is_ok());
    }

    #[test]
    fn forged_signature_rejected() {
        let (card, nonce, secret) = fixtures();
        let mut a = mint(&card, &nonce, &secret);
        a.sig[10] ^= 0xff; // corrupt one signature byte
        let err = verify_link_assertion(&a, &card, &nonce).unwrap_err();
        assert!(matches!(err, CoreError::Assertion(_)), "got: {err}");
    }

    #[test]
    fn wrong_card_rejected() {
        let (card, nonce, secret) = fixtures();
        let a = mint(&card, &nonce, &secret);
        let other_card = Identity::mint().card();
        assert!(verify_link_assertion(&a, &other_card, &nonce).is_err(), "different card must not verify");
    }

    #[test]
    fn wrong_nonce_rejected() {
        let (card, nonce, secret) = fixtures();
        let a = mint(&card, &nonce, &secret);
        assert!(verify_link_assertion(&a, &card, &Nonce::mint()).is_err(), "different nonce must not verify");
    }

    #[test]
    fn wrong_npub_rejected() {
        // A signature minted by one hoard key, presented with a *different* npub, must not verify.
        let (card, nonce, secret) = fixtures();
        let mut a = mint(&card, &nonce, &secret);
        let impostor = mint(&card, &nonce, &[0x22u8; 32]);
        a.npub = impostor.npub; // keep the original sig, swap in a foreign npub
        assert!(verify_link_assertion(&a, &card, &nonce).is_err());
    }

    // --- Suite MAB: malformed inputs are refused with a reason, never a panic. ---

    #[test]
    fn mab_malformed_signature_and_npub_rejected() {
        let (card, nonce, _secret) = fixtures();
        // Too-short signature.
        let short = LinkAssertion { npub: [1u8; 32], sig: vec![0u8; 10] };
        assert!(matches!(verify_link_assertion(&short, &card, &nonce), Err(CoreError::Assertion(_))));
        // 64 bytes but not a valid signature, and an all-zero npub (not a valid x-only key).
        let junk = LinkAssertion { npub: [0u8; 32], sig: vec![0u8; 64] };
        assert!(matches!(verify_link_assertion(&junk, &card, &nonce), Err(CoreError::Assertion(_))));
    }
}
