//! Consent is structural (MAS-INV-4, DESIGN §5). `mascara-net`'s dial API requires a
//! [`ConsentAck`] value that only [`acknowledge_ip_exposure`] produces — there is no code path
//! from "ticket opened" to "bytes moving" that skips it. This is in-process and advisory by
//! nature (a determined caller could still fabricate a value with `unsafe`/reflection tricks),
//! but it makes MAS-INV-4 grep-able and un-forgettable in review: the dialer's public transfer
//! function (`dialer::pull`) takes a `ConsentAck` by value, so removing the call is a compile
//! error, not a silent behavior change (`sem_no_bytes_before_consent`).
//!
//! CLI `--yes` still **prints** the notice before constructing the ack (spec §CLI, MAS-INV-4) —
//! see `mascara-cli`'s `cmd_recv` (`sem_consent_notice_always_printed`).

/// The exact IP-exposure notice text (spec §Download step 2). Front-ends print this **verbatim**
/// before asking for consent — the real privacy property, never softened (`sem_consent_copy_binding_tier`):
/// this is a direct, unhidden transfer, every time, with no anonymity claim.
pub const IP_EXPOSURE_NOTICE: &str =
    "Direct transfer — the sharer will see your IP. Mascara has no IP-hiding mode. Continue?";

/// The **stage-2 reminder** for a folder receive (DESIGN §5, amended 2026-07-27 — codex #5).
///
/// A folder pull opens a SECOND connection, so the honest question is what that second connection
/// discloses. The answer is: nothing new. Stage 1 already showed [`IP_EXPOSURE_NOTICE`] and
/// obtained consent, and the second dial goes to the **same sharer, who already has the IP** —
/// so re-printing the full notice would repeat a disclosure verbatim without conveying a new fact.
///
/// What the receiver DOES need at stage 2 is to know that the start action opens that connection
/// now, having just seen the file list and total. This line says exactly that, and front-ends
/// print it **unconditionally — including under `--yes`** (`sem_consent_notice_always_printed`),
/// so a scripted transfer never goes silent at the moment the second connection opens.
///
/// Binding-tier copy like the notice itself: it may be made clearer, never softer
/// (`sem_consent_copy_binding_tier`).
pub const IP_EXPOSURE_REMINDER: &str =
    "Starting the download opens a second direct connection to the same sharer — the IP exposure \
     disclosed above applies to it too.";

/// Proof that [`IP_EXPOSURE_NOTICE`] was shown to the user. The field is private to this module,
/// so the **only** way to construct one is [`acknowledge_ip_exposure`] — that is the whole
/// mechanism (DESIGN §5).
pub struct ConsentAck(());

/// Acknowledge the IP-exposure notice and produce the [`ConsentAck`] the dialer requires. The
/// caller (CLI/GUI) MUST have shown [`IP_EXPOSURE_NOTICE`] to the user first — the type system
/// cannot compel *that*, but it makes the call, and any path that skips it, mechanically checkable
/// (a source sweep asserts every dial path requires this type — see
/// `mascara-core/tests/semantic_guards.rs`).
pub fn acknowledge_ip_exposure() -> ConsentAck {
    ConsentAck(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sem_no_bytes_before_consent`'s behavioural half: the ack is constructible at all, only
    /// via this function (the structural half — no OTHER path skips it — is a source sweep in
    /// `mascara-core/tests/semantic_guards.rs`, since that is where the sweep convention lives).
    #[test]
    fn ack_is_constructible_via_the_one_function() {
        let _ack: ConsentAck = acknowledge_ip_exposure();
    }

    /// `sem_consent_copy_binding_tier`, stage-2 form: the folder reminder must name the second
    /// connection and point at the disclosure that covers it — never imply the download is
    /// somehow private, and never soften what stage 1 said.
    #[test]
    fn reminder_names_the_second_connection_honestly() {
        let lower = IP_EXPOSURE_REMINDER.to_lowercase();
        assert!(
            lower.contains("second direct connection"),
            "must name the second connection: {IP_EXPOSURE_REMINDER}"
        );
        assert!(
            lower.contains("ip exposure"),
            "must point at the IP exposure it inherits: {IP_EXPOSURE_REMINDER}"
        );
        assert!(
            !lower.contains("anonymous") && !lower.contains("private") && !lower.contains("secure"),
            "must not oversell privacy it does not deliver (MAS-INV-4): {IP_EXPOSURE_REMINDER}"
        );
    }

    /// `sem_consent_notice_always_printed` / `sem_consent_copy_binding_tier`: the notice must name
    /// the real property (IP exposure, no hiding mode) — never a softened or misleading claim.
    #[test]
    fn notice_states_the_real_property_honestly() {
        let lower = IP_EXPOSURE_NOTICE.to_lowercase();
        assert!(lower.contains("ip"), "must name the IP exposure: {IP_EXPOSURE_NOTICE}");
        assert!(
            lower.contains("no ip-hiding") || lower.contains("no hiding"),
            "must state there is no hiding mode: {IP_EXPOSURE_NOTICE}"
        );
        assert!(
            !lower.contains("anonymous") && !lower.contains("private"),
            "must not oversell privacy it does not deliver (MAS-INV-4): {IP_EXPOSURE_NOTICE}"
        );
    }
}
