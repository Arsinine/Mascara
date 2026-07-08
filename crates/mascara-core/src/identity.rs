//! The Mascara identity: two independent keypairs under one card (spec D10, DESIGN.md §2).
//!
//! One job per key, no cross-primitive reuse:
//! - **transport** (ed25519) — becomes the iroh endpoint identity in `mascara-net`; the public
//!   half is what a receiver pins before dialing (spec MT3).
//! - **sealing** (X25519) — an age-style recipient key; senders encrypt tickets to the public
//!   half (spec MT5: sealed to the recipient).
//!
//! Minted together, rotated together (rotation invalidates the old card and every ticket sealed
//! to the old keys — spec D3). MAS-INV-1: this is never the Hoardbook `npub` and never derived
//! from it.

use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use x25519_dalek::StaticSecret;

use crate::card::{binding_message, Card};

pub struct Identity {
    transport: SigningKey,
    sealing: StaticSecret,
}

impl Identity {
    /// Mint a fresh identity: both keypairs from OS randomness, independently.
    pub fn mint() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut tb = [0u8; 32];
        rng.fill_bytes(&mut tb);
        let mut sb = [0u8; 32];
        rng.fill_bytes(&mut sb);
        let id = Self::from_secret_bytes(&tb, &sb);
        // Local copies of secret material are scrubbed once the keys own them.
        use zeroize::Zeroize;
        tb.zeroize();
        sb.zeroize();
        id
    }

    /// Rebuild an identity from stored secret bytes (the keystore's job to fetch them safely).
    pub fn from_secret_bytes(transport_sk: &[u8; 32], sealing_sk: &[u8; 32]) -> Self {
        Self {
            transport: SigningKey::from_bytes(transport_sk),
            sealing: StaticSecret::from(*sealing_sk),
        }
    }

    /// The public contact card for this identity — the only thing that is ever handed out. The
    /// transport key signs the sealing key into the card (the H1 binding, see `card.rs`).
    pub fn card(&self) -> Card {
        let sealing_pk = x25519_dalek::PublicKey::from(&self.sealing).to_bytes();
        let binding_sig = self.transport.sign(&binding_message(&sealing_pk)).to_bytes();
        Card {
            transport_pk: self.transport.verifying_key().to_bytes(),
            sealing_pk,
            binding_sig,
        }
    }

    /// Raw transport secret — consumed by `mascara-net` to construct the iroh `SecretKey`
    /// (keeping this crate free of the iroh dependency). Handle with care; do not persist
    /// outside the keystore.
    pub fn transport_secret_bytes(&self) -> [u8; 32] {
        self.transport.to_bytes()
    }

    /// Raw sealing secret — consumed by the ticket module (M1) to open sealed tickets.
    /// Handle with care; do not persist outside the keystore.
    pub fn sealing_secret_bytes(&self) -> [u8; 32] {
        self.sealing.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_produces_independent_keys() {
        let id = Identity::mint();
        // The two secrets must be independent — a shared or derived key would re-introduce the
        // cross-primitive reuse D10 exists to avoid.
        assert_ne!(id.transport_secret_bytes(), id.sealing_secret_bytes());
    }

    #[test]
    fn two_mints_never_collide() {
        let a = Identity::mint();
        let b = Identity::mint();
        assert_ne!(a.card().transport_pk, b.card().transport_pk);
        assert_ne!(a.card().sealing_pk, b.card().sealing_pk);
    }

    #[test]
    fn from_secret_bytes_round_trips() {
        let id = Identity::mint();
        let rebuilt =
            Identity::from_secret_bytes(&id.transport_secret_bytes(), &id.sealing_secret_bytes());
        assert_eq!(id.card(), rebuilt.card());
    }
}
