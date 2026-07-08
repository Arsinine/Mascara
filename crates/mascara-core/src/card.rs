//! The contact card (spec D3/D10, DESIGN.md §2): a short, IP-free string carrying the two PUBLIC
//! keys and the proof they belong together —
//! `bech32m("mascara", 0x01 || ed25519 transport pk || X25519 sealing pk || binding sig)`.
//!
//! The **binding signature** (chorus H1) is an ed25519 self-signature by the transport key over
//! `"mascara-card-v1" || sealing pk`. Without it the card is a bare concatenation, and a MITM on
//! the out-of-band card handoff could swap in their own sealing half — keeping the victim's
//! transport key — and silently read the endpoint addresses inside tickets sealed to the tampered
//! card (an MT2/MAS-INV-3 bruise). `parse` verifies it; an unbound card never parses.
//!
//! bech32m buys three things a bare base64 blob would not: a human-recognizable `mascara1…`
//! prefix, a checksum (a corrupted paste fails loudly instead of sealing a ticket to garbage),
//! and a version byte for forward evolution. The conventional 90-char bech32 length cap is
//! waived, as bolt11 does — a card is ~220 chars and is pasted, never typed.
//!
//! The card is deliberately *reusable and stable* (D3): a standing identifier until rotated.
//! It contains no address — reachability rides only inside sealed tickets (MAS-INV-3).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::CoreError;

pub const CARD_HRP: &str = "mascara";
pub const CARD_VERSION: u8 = 1;
/// Domain-separation context for the binding signature (versioned with the card format).
pub const CARD_BINDING_CONTEXT: &[u8] = b"mascara-card-v1";
/// version byte + two 32-byte public keys + 64-byte binding signature.
const CARD_PAYLOAD_LEN: usize = 1 + 32 + 32 + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Card {
    /// ed25519 — the iroh transport identity the receiver pins before dialing.
    pub transport_pk: [u8; 32],
    /// X25519 — the age-style sealing key senders encrypt tickets to.
    pub sealing_pk: [u8; 32],
    /// ed25519 self-signature by `transport_pk` over `CARD_BINDING_CONTEXT || sealing_pk`.
    pub binding_sig: [u8; 64],
}

/// The exact bytes the binding signature covers.
pub(crate) fn binding_message(sealing_pk: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CARD_BINDING_CONTEXT.len() + 32);
    msg.extend_from_slice(CARD_BINDING_CONTEXT);
    msg.extend_from_slice(sealing_pk);
    msg
}

impl Card {
    /// Encode as the card string (`mascara1…`).
    pub fn encode(&self) -> String {
        let mut payload = Vec::with_capacity(CARD_PAYLOAD_LEN);
        payload.push(CARD_VERSION);
        payload.extend_from_slice(&self.transport_pk);
        payload.extend_from_slice(&self.sealing_pk);
        payload.extend_from_slice(&self.binding_sig);
        let hrp = Hrp::parse(CARD_HRP).expect("static hrp is valid");
        bech32::encode::<Bech32m>(hrp, &payload).expect("card payload is well under bech32 limits")
    }

    /// Parse and validate a pasted card. Every failure is reasoned — the paste channel is the
    /// trust channel (MT3), so "almost right" must never silently become "close enough".
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let checked = CheckedHrpstring::new::<Bech32m>(s.trim())
            .map_err(|e| CoreError::InvalidCard(format!("not a valid card string: {e}")))?;
        if checked.hrp().to_lowercase() != CARD_HRP {
            return Err(CoreError::InvalidCard(format!(
                "wrong prefix '{}' — a Mascara card starts with '{CARD_HRP}1'",
                checked.hrp()
            )));
        }
        let payload: Vec<u8> = checked.byte_iter().collect();
        if payload.len() != CARD_PAYLOAD_LEN {
            return Err(CoreError::InvalidCard(format!(
                "wrong payload length {} (expected {CARD_PAYLOAD_LEN})",
                payload.len()
            )));
        }
        if payload[0] != CARD_VERSION {
            return Err(CoreError::InvalidCard(format!(
                "unsupported card version {} (this Mascara understands v{CARD_VERSION})",
                payload[0]
            )));
        }
        let mut transport_pk = [0u8; 32];
        transport_pk.copy_from_slice(&payload[1..33]);
        let mut sealing_pk = [0u8; 32];
        sealing_pk.copy_from_slice(&payload[33..65]);
        let mut binding_sig = [0u8; 64];
        binding_sig.copy_from_slice(&payload[65..129]);

        // H1: the transport key must vouch for the sealing key, or the two halves may not belong
        // to the same person.
        let vk = VerifyingKey::from_bytes(&transport_pk).map_err(|e| {
            CoreError::InvalidCard(format!("transport key is not a valid ed25519 key: {e}"))
        })?;
        vk.verify_strict(&binding_message(&sealing_pk), &Signature::from_bytes(&binding_sig))
            .map_err(|_| {
                CoreError::InvalidCard(
                    "the card's keys are not bound to each other — the card was assembled or \
                     tampered with, do not use it"
                        .into(),
                )
            })?;

        Ok(Card { transport_pk, sealing_pk, binding_sig })
    }
}

impl std::fmt::Display for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn encode_raw(version: u8, body: &[u8]) -> String {
        let hrp = Hrp::parse(CARD_HRP).unwrap();
        let mut payload = vec![version];
        payload.extend_from_slice(body);
        bech32::encode::<Bech32m>(hrp, &payload).unwrap()
    }

    #[test]
    fn round_trip() {
        let card = Identity::mint().card();
        let s = card.encode();
        assert!(s.starts_with("mascara1"), "got: {s}");
        assert_eq!(Card::parse(&s).unwrap(), card);
    }

    #[test]
    fn whitespace_around_paste_is_tolerated() {
        let card = Identity::mint().card();
        let s = format!("  {}\n", card.encode());
        assert_eq!(Card::parse(&s).unwrap(), card);
    }

    #[test]
    fn corrupted_character_fails_checksum() {
        let s = Identity::mint().card().encode();
        // Flip one data character (past the 'mascara1' prefix) to a different bech32 char.
        let mut chars: Vec<char> = s.chars().collect();
        let i = 20;
        chars[i] = if chars[i] == 'q' { 'p' } else { 'q' };
        let tampered: String = chars.into_iter().collect();
        assert!(Card::parse(&tampered).is_err(), "corrupted card must not parse");
    }

    #[test]
    fn swapped_sealing_key_rejected_as_unbound() {
        // H1: a MITM keeps Alice's transport key but swaps in Mallory's sealing key. The binding
        // signature no longer verifies — the assembled card must not parse.
        let alice = Identity::mint().card();
        let mallory = Identity::mint().card();
        let franken = Card {
            transport_pk: alice.transport_pk,
            sealing_pk: mallory.sealing_pk,
            binding_sig: alice.binding_sig,
        };
        let err = Card::parse(&franken.encode()).unwrap_err().to_string();
        assert!(err.contains("not bound"), "got: {err}");
    }

    #[test]
    fn foreign_binding_sig_rejected() {
        // Even a *valid* signature from the wrong transport key must not bind.
        let alice = Identity::mint().card();
        let mallory = Identity::mint().card();
        let franken = Card {
            transport_pk: alice.transport_pk,
            sealing_pk: mallory.sealing_pk,
            binding_sig: mallory.binding_sig, // Mallory's sig, but over Mallory's key with Mallory's transport
        };
        assert!(Card::parse(&franken.encode()).is_err());
    }

    #[test]
    fn wrong_hrp_rejected_with_reason() {
        let hrp = Hrp::parse("notmascara").unwrap();
        let payload = [CARD_VERSION].iter().copied().chain([0u8; 128]).collect::<Vec<_>>();
        let s = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        let err = Card::parse(&s).unwrap_err().to_string();
        assert!(err.contains("wrong prefix"), "got: {err}");
    }

    #[test]
    fn wrong_version_rejected_with_reason() {
        let s = encode_raw(9, &[0u8; 128]);
        let err = Card::parse(&s).unwrap_err().to_string();
        assert!(err.contains("unsupported card version"), "got: {err}");
    }

    #[test]
    fn truncated_payload_rejected() {
        let s = encode_raw(CARD_VERSION, &[0u8; 64]);
        let err = Card::parse(&s).unwrap_err().to_string();
        assert!(err.contains("wrong payload length"), "got: {err}");
    }

    #[test]
    fn uppercase_form_parses() {
        // bech32 permits an all-uppercase string (QR alphanumeric mode); mixed case is invalid.
        let card = Identity::mint().card();
        assert_eq!(Card::parse(&card.encode().to_uppercase()).unwrap(), card);
    }

    #[test]
    fn plain_bech32_checksum_rejected() {
        // A card must be bech32m specifically — the non-m checksum is a different format.
        let hrp = Hrp::parse(CARD_HRP).unwrap();
        let payload = [CARD_VERSION].iter().copied().chain([0u8; 128]).collect::<Vec<_>>();
        let s = bech32::encode::<bech32::Bech32>(hrp, &payload).unwrap();
        assert!(Card::parse(&s).is_err(), "bech32 (non-m) checksum must not parse");
    }
}
