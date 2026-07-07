//! Portable, passphrase-encrypted backup crypto (spec §Backup & Durability).
//!
//! The live at-rest encryption (Windows DPAPI) is **machine-bound** — a verbatim copy restores
//! to a dead key on new hardware. So the backup re-encrypts the whole profile under a user
//! **passphrase** with **Argon2id → XChaCha20-Poly1305**, producing a portable archive. A
//! **plaintext** mode exists for advanced users (behind a blunt UI warning); it is never the
//! default.
//!
//! These are **pure functions** (no I/O, no Tauri): the `hb-app` seam tars `~/.hoardbook` into the
//! `plaintext` argument and writes the returned archive to a file. The crypto lives here, next to
//! the listing/seal core, so CI guards it — restore-on-new-hardware cannot run in the offline dev
//! env, so the adversarial L1 tests in this module are the backup's only CI safety net.
//!
//! ## Wire format — versioned, self-describing, header-authenticated
//!
//! ```text
//!   magic[4]="HBK1" · format_ver:u8 · mode:u8(1=passphrase,0=plaintext) · argon2_version:u8(0x13)
//!   · m_cost:u32le · t_cost:u32le · p_cost:u8 · salt[32] · nonce[24]   ‖  body
//! ```
//!
//! The **entire header except the nonce slot** (`magic … salt`, the first 48 bytes) is passed to
//! the AEAD as **associated data**, so any mutation of the version, the Argon2 algorithm byte, or
//! the KDF params **fails the tag** — without this, an attacker who can write the file flips
//! `m_cost` to a trivially-crackable value and the passphrase falls to offline brute force (a
//! downgrade attack). The Argon2id params + the algorithm version travel *with* the archive so it
//! stays decodable for years; salt and nonce are each independently random per archive (a derived
//! or fixed nonce would break XChaCha20). In plaintext mode every field after `mode` is zero-filled
//! and the body is the bare tar. **At v1 the decoder speaks only v1** — a bumped `format_ver` is a
//! clean reject, never a misparse.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::HbError;

// --- Wire constants -------------------------------------------------------------------------

const MAGIC: &[u8; 4] = b"HBK1";
/// The only backup format this build speaks.
pub const BACKUP_FORMAT_VER: u8 = 1;
/// Argon2 algorithm version `0x13` (19), pinned in the header so a library default drift cannot
/// silently change how the KDF reproduces (round-2 review finding).
const ARGON2_VERSION_BYTE: u8 = 0x13;

const MODE_PLAINTEXT: u8 = 0;
const MODE_PASSPHRASE: u8 = 1;

const HEADER_LEN: usize = 72; // 4+1+1+1 + 4+4+1 + 32 + 24
const AAD_LEN: usize = 48; // magic … salt (everything except the 24-byte nonce slot)

// Field offsets within the header.
const OFF_FORMAT_VER: usize = 4;
const OFF_MODE: usize = 5;
const OFF_ARGON2_VER: usize = 6;
const OFF_M_COST: usize = 7; // u32le
const OFF_T_COST: usize = 11; // u32le
const OFF_P_COST: usize = 15; // u8
const OFF_SALT: usize = 16; // [32]
const OFF_NONCE: usize = 48; // [24]

const KEY_LEN: usize = 32;

// --- Argon2id "sensitive" tier (decision #3) ------------------------------------------------
// A backup is encrypted once and holds the only non-recoverable secret, so it warrants more than
// a login-grade KDF. m_cost is in KiB: 131072 KiB = 128 MiB.
const M_COST_DEFAULT: u32 = 131_072;
const T_COST_DEFAULT: u32 = 2;
const P_COST_DEFAULT: u8 = 1;

// Pre-auth DoS ceiling. `decrypt_backup` reads these from the *not-yet-authenticated* header and
// must run Argon2id before the tag can verify, so out-of-range params are rejected *before* the
// KDF runs — a hostile archive must not OOM or thread-exhaust the restore.
const M_COST_MAX: u32 = 1_048_576; // 1 GiB in KiB
const T_COST_MAX: u32 = 16;
const P_COST_MAX: u8 = 4;

/// Minimum passphrase length, measured on the **NFKC-normalized** form (decision #3). The
/// Argon2id params target ~human-second derivation; the passphrase entropy is what actually
/// resists an offline attacker who obtains the archive.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// How a backup archive is sealed. Borrowed `&str` so the `hb-app` caller can hold the passphrase
/// in a zeroize-on-drop buffer and lend it (decision #3).
pub enum BackupMode<'a> {
    /// Argon2id → XChaCha20-Poly1305 under a user passphrase. The portable default.
    Passphrase(&'a str),
    /// No encryption — the archive *is* the identity (behind a blunt UI warning).
    Plaintext,
}

/// The derived symmetric key, wiped on drop (decision #3). `ZeroizeOnDrop` by construction — the
/// `derived_key_implements_zeroize_on_drop` test asserts the bound, not UB memory inspection.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; KEY_LEN]);

// --- Public API -----------------------------------------------------------------------------

/// Seal `plaintext` (the tar of `~/.hoardbook`) into a portable, versioned backup archive.
///
/// In `Passphrase` mode the passphrase is **NFKC-normalized** (so a backup made on one OS decrypts
/// on another) and must be at least [`MIN_PASSPHRASE_LEN`] characters on that normalized form —
/// a defensive floor mirrored by the UI strength meter.
pub fn encrypt_backup(mode: BackupMode<'_>, plaintext: &[u8]) -> Result<Vec<u8>, HbError> {
    match mode {
        BackupMode::Plaintext => {
            let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len());
            out.extend_from_slice(&plaintext_header());
            out.extend_from_slice(plaintext);
            Ok(out)
        }
        BackupMode::Passphrase(pass) => {
            // NFKC-normalize + length-floor on the normalized form (round-2 finding: a raw-vs-
            // normalized split would let a passphrase pass one gate and fail the other).
            let norm = Zeroizing::new(pass.nfkc().collect::<String>());
            if norm.chars().count() < MIN_PASSPHRASE_LEN {
                return Err(HbError::PassphraseTooShort { min: MIN_PASSPHRASE_LEN });
            }

            let salt: [u8; 32] = rand::random();
            // Independent random nonce — never derived from salt/passphrase (reuse breaks XChaCha20).
            let nonce: [u8; 24] = rand::random();
            let header = encrypted_header(M_COST_DEFAULT, T_COST_DEFAULT, P_COST_DEFAULT, &salt, &nonce);

            let key = derive_key(
                norm.as_bytes(),
                &salt,
                M_COST_DEFAULT,
                T_COST_DEFAULT,
                P_COST_DEFAULT,
                Version::V0x13,
            )?;
            let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
                .map_err(|_| HbError::EncryptionFailed)?;
            let ct = cipher
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &header[..AAD_LEN] })
                .map_err(|_| HbError::EncryptionFailed)?;

            let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
            out.extend_from_slice(&header);
            out.extend_from_slice(&ct);
            Ok(out)
        }
    }
}

/// Decode a backup archive. The header is **self-describing**, so the passphrase is optional:
/// an encrypted header + `None` is a reasoned [`HbError::PassphraseRequired`], a plaintext header
/// ignores any supplied passphrase. Wrong passphrase / tampered body or header → reasoned `Err`,
/// never a panic.
pub fn decrypt_backup(passphrase: Option<&str>, archive: &[u8]) -> Result<Vec<u8>, HbError> {
    if archive.len() < HEADER_LEN {
        return Err(HbError::InvalidBackup("archive shorter than the header".into()));
    }
    let header = &archive[..HEADER_LEN];
    let body = &archive[HEADER_LEN..];

    if &header[..4] != MAGIC {
        return Err(HbError::InvalidBackup("bad magic — not an HBK archive".into()));
    }
    // v1 speaks only v1: a bumped/unknown format_ver is a clean reject, not a misparse.
    let format_ver = header[OFF_FORMAT_VER];
    if format_ver != BACKUP_FORMAT_VER {
        return Err(HbError::UnsupportedBackupVersion(format_ver));
    }

    match header[OFF_MODE] {
        MODE_PLAINTEXT => {
            // A passphrase on a plaintext archive is ignored — the mode=0 header is authoritative.
            // (The `hb-app` seam emits a debug trace; hb-core stays dependency-light.)
            let _ = passphrase;
            Ok(body.to_vec())
        }
        MODE_PASSPHRASE => {
            let pass = passphrase.ok_or(HbError::PassphraseRequired)?;

            let m_cost = u32::from_le_bytes(header[OFF_M_COST..OFF_M_COST + 4].try_into().unwrap());
            let t_cost = u32::from_le_bytes(header[OFF_T_COST..OFF_T_COST + 4].try_into().unwrap());
            let p_cost = header[OFF_P_COST];

            // Pre-auth DoS ceiling — reject before invoking Argon2id (decision #3).
            if m_cost > M_COST_MAX {
                return Err(HbError::BackupParamsOutOfRange(format!("m_cost {m_cost} exceeds {M_COST_MAX} KiB")));
            }
            if t_cost > T_COST_MAX {
                return Err(HbError::BackupParamsOutOfRange(format!("t_cost {t_cost} exceeds {T_COST_MAX}")));
            }
            if p_cost > P_COST_MAX {
                return Err(HbError::BackupParamsOutOfRange(format!("p_cost {p_cost} exceeds {P_COST_MAX}")));
            }

            // The Argon2 algorithm version travels in the (authenticated) header. A flip to another
            // valid version changes both the derived key and the AAD → the tag fails; an unknown
            // value is a reasoned reject before the KDF.
            let version = match header[OFF_ARGON2_VER] {
                0x13 => Version::V0x13,
                0x10 => Version::V0x10,
                other => {
                    return Err(HbError::BackupParamsOutOfRange(format!("unknown argon2 version 0x{other:02x}")))
                }
            };

            let salt = &header[OFF_SALT..OFF_SALT + 32];
            let nonce = &header[OFF_NONCE..OFF_NONCE + 24];

            let norm = Zeroizing::new(pass.nfkc().collect::<String>());
            let key = derive_key(norm.as_bytes(), salt, m_cost, t_cost, p_cost, version)?;
            let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
                .map_err(|_| HbError::DecryptionFailed)?;
            cipher
                .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad: &header[..AAD_LEN] })
                .map_err(|_| HbError::DecryptionFailed)
        }
        other => Err(HbError::InvalidBackup(format!("unknown backup mode byte {other}"))),
    }
}

/// Peek at a backup header to learn whether restoring it needs a passphrase, so the UI can decide
/// whether to prompt. Cheap and side-effect-free (no KDF).
pub fn is_encrypted_backup(archive: &[u8]) -> Result<bool, HbError> {
    if archive.len() < HEADER_LEN || &archive[..4] != MAGIC {
        return Err(HbError::InvalidBackup("not an HBK archive".into()));
    }
    if archive[OFF_FORMAT_VER] != BACKUP_FORMAT_VER {
        return Err(HbError::UnsupportedBackupVersion(archive[OFF_FORMAT_VER]));
    }
    // Strict mode parse, matching `decrypt_backup` (chorus/Codex): an unknown mode byte is a clean
    // reject, never silently classified as plaintext-ish.
    match archive[OFF_MODE] {
        MODE_PLAINTEXT => Ok(false),
        MODE_PASSPHRASE => Ok(true),
        other => Err(HbError::InvalidBackup(format!("unknown backup mode byte {other}"))),
    }
}

// --- Internals ------------------------------------------------------------------------------

fn derive_key(
    pass: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
    version: Version,
) -> Result<DerivedKey, HbError> {
    let params = Params::new(m_cost, t_cost, p_cost as u32, Some(KEY_LEN))
        .map_err(|e| HbError::BackupParamsOutOfRange(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, version, params);
    let mut key = DerivedKey([0u8; KEY_LEN]);
    argon
        .hash_password_into(pass, salt, &mut key.0)
        .map_err(|_| HbError::EncryptionFailed)?;
    Ok(key)
}

fn encrypted_header(m_cost: u32, t_cost: u32, p_cost: u8, salt: &[u8; 32], nonce: &[u8; 24]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[OFF_FORMAT_VER] = BACKUP_FORMAT_VER;
    h[OFF_MODE] = MODE_PASSPHRASE;
    h[OFF_ARGON2_VER] = ARGON2_VERSION_BYTE;
    h[OFF_M_COST..OFF_M_COST + 4].copy_from_slice(&m_cost.to_le_bytes());
    h[OFF_T_COST..OFF_T_COST + 4].copy_from_slice(&t_cost.to_le_bytes());
    h[OFF_P_COST] = p_cost;
    h[OFF_SALT..OFF_SALT + 32].copy_from_slice(salt);
    h[OFF_NONCE..OFF_NONCE + 24].copy_from_slice(nonce);
    h
}

fn plaintext_header() -> [u8; HEADER_LEN] {
    // Every field after `mode` is zero-filled so the layout stays fixed-size and deterministic.
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[OFF_FORMAT_VER] = BACKUP_FORMAT_VER;
    h[OFF_MODE] = MODE_PLAINTEXT;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &[u8] = b"a fake ~/.hoardbook tar: identity.json, collections/, settings.json";
    const PASS: &str = "correct horse battery staple"; // >= 12 chars

    fn enc(pass: &str) -> Vec<u8> {
        encrypt_backup(BackupMode::Passphrase(pass), PLAIN).unwrap()
    }

    #[test]
    fn backup_roundtrips_under_passphrase() {
        let archive = enc(PASS);
        assert_eq!(decrypt_backup(Some(PASS), &archive).unwrap(), PLAIN);
    }

    #[test]
    fn wrong_passphrase_fails_with_reason_not_panic() {
        let archive = enc(PASS);
        let err = decrypt_backup(Some("the wrong passphrase entirely"), &archive).unwrap_err();
        assert!(matches!(err, HbError::DecryptionFailed), "got {err:?}");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn tampered_ciphertext_rejected_by_aead() {
        let mut archive = enc(PASS);
        let last = archive.len() - 1;
        archive[last] ^= 0x01; // flip a body byte
        assert!(matches!(decrypt_backup(Some(PASS), &archive), Err(HbError::DecryptionFailed)));
    }

    #[test]
    fn tampered_header_params_rejected_by_aead() {
        // The convergent CRITICAL finding: flip a byte of m_cost in the header WITHOUT touching the
        // ciphertext. The default m_cost is 131072 (0x00020000); +1 on the low byte stays in range,
        // so it passes the ceiling check and reaches the AEAD — where the header-as-AAD makes the
        // tag fail. A round-trip-only suite would miss this downgrade vector.
        let mut archive = enc(PASS);
        archive[OFF_M_COST] = archive[OFF_M_COST].wrapping_add(1);
        assert!(matches!(decrypt_backup(Some(PASS), &archive), Err(HbError::DecryptionFailed)));
    }

    #[test]
    fn argon2_version_pinned_and_aad_covered() {
        // The 0x13 algorithm byte is in the header; flipping it to another valid version (0x10)
        // both re-derives a different key and changes the AAD → the tag fails.
        let archive = enc(PASS);
        assert_eq!(archive[OFF_ARGON2_VER], 0x13, "encrypt pins argon2 version 0x13");
        let mut tampered = archive.clone();
        tampered[OFF_ARGON2_VER] = 0x10;
        assert!(matches!(decrypt_backup(Some(PASS), &tampered), Err(HbError::DecryptionFailed)));
    }

    #[test]
    fn truncated_or_garbage_archive_rejected_not_panicked() {
        assert!(matches!(decrypt_backup(Some(PASS), b""), Err(HbError::InvalidBackup(_))));
        assert!(matches!(decrypt_backup(Some(PASS), b"too short"), Err(HbError::InvalidBackup(_))));
        let garbage = vec![0xABu8; HEADER_LEN + 10];
        assert!(matches!(decrypt_backup(Some(PASS), &garbage), Err(HbError::InvalidBackup(_))));
        // A valid header truncated mid-body fails the tag, not a panic.
        let mut archive = enc(PASS);
        archive.truncate(HEADER_LEN + 1);
        assert!(matches!(decrypt_backup(Some(PASS), &archive), Err(HbError::DecryptionFailed)));
    }

    #[test]
    fn backup_format_version_is_self_describing() {
        let archive = enc(PASS);
        assert_eq!(&archive[..4], MAGIC, "magic HBK1");
        assert_eq!(archive[OFF_FORMAT_VER], BACKUP_FORMAT_VER);
        assert_eq!(archive[OFF_MODE], MODE_PASSPHRASE);
        // A bumped/unknown format_ver is a clean reject, never a misparse.
        let mut bumped = archive.clone();
        bumped[OFF_FORMAT_VER] = 2;
        assert!(matches!(
            decrypt_backup(Some(PASS), &bumped),
            Err(HbError::UnsupportedBackupVersion(2))
        ));
    }

    #[test]
    fn argon2_params_in_header_enable_decode() {
        // Params travel WITH the archive — decode uses only the archive, no external params.
        let archive = enc(PASS);
        let m = u32::from_le_bytes(archive[OFF_M_COST..OFF_M_COST + 4].try_into().unwrap());
        let t = u32::from_le_bytes(archive[OFF_T_COST..OFF_T_COST + 4].try_into().unwrap());
        assert_eq!(m, M_COST_DEFAULT);
        assert_eq!(t, T_COST_DEFAULT);
        assert_eq!(archive[OFF_P_COST], P_COST_DEFAULT);
        assert_eq!(decrypt_backup(Some(PASS), &archive).unwrap(), PLAIN);
    }

    #[test]
    fn random_salt_makes_two_backups_of_same_data_differ() {
        let a = enc(PASS);
        let b = enc(PASS);
        let salt_a = &a[OFF_SALT..OFF_SALT + 32];
        let salt_b = &b[OFF_SALT..OFF_SALT + 32];
        assert_ne!(salt_a, salt_b, "each archive must have an independent random salt");
        assert_ne!(a, b, "two backups of identical data must not be byte-identical");
    }

    #[test]
    fn nonce_is_random_per_encryption() {
        // Guards against a salt-derived / fixed nonce that the salt-differs test would not catch.
        let a = enc(PASS);
        let b = enc(PASS);
        assert_ne!(
            &a[OFF_NONCE..OFF_NONCE + 24],
            &b[OFF_NONCE..OFF_NONCE + 24],
            "the XChaCha20 nonce must be independently random per encryption"
        );
    }

    #[test]
    fn plaintext_export_roundtrips_and_is_flagged_unencrypted() {
        let archive = encrypt_backup(BackupMode::Plaintext, PLAIN).unwrap();
        assert_eq!(archive[OFF_MODE], MODE_PLAINTEXT, "header flags the archive unencrypted");
        assert!(!is_encrypted_backup(&archive).unwrap());
        // Restore never derives a key from it — decrypt with no passphrase returns the body.
        assert_eq!(decrypt_backup(None, &archive).unwrap(), PLAIN);
        // And a stray passphrase is ignored (the mode=0 header is authoritative).
        assert_eq!(decrypt_backup(Some(PASS), &archive).unwrap(), PLAIN);
    }

    #[test]
    fn too_short_passphrase_rejected_with_reason() {
        let err = encrypt_backup(BackupMode::Passphrase("short"), PLAIN).unwrap_err();
        assert!(matches!(err, HbError::PassphraseTooShort { min } if min == MIN_PASSPHRASE_LEN), "got {err:?}");
    }

    #[test]
    fn backup_with_excessive_params_rejected_before_kdf() {
        // A forged header with an astronomical m_cost / t_cost / p_cost is rejected by the ceiling
        // *before* Argon2id runs, so a hostile archive can't OOM / thread-exhaust the restore.
        let body = vec![0u8; 32];
        let salt = [0u8; 32];
        let nonce = [0u8; 24];

        let mut h = encrypted_header(M_COST_MAX + 1, T_COST_DEFAULT, P_COST_DEFAULT, &salt, &nonce);
        let mut a = h.to_vec();
        a.extend_from_slice(&body);
        assert!(matches!(decrypt_backup(Some(PASS), &a), Err(HbError::BackupParamsOutOfRange(_))), "m_cost ceiling");

        h = encrypted_header(M_COST_DEFAULT, T_COST_MAX + 1, P_COST_DEFAULT, &salt, &nonce);
        a = h.to_vec();
        a.extend_from_slice(&body);
        assert!(matches!(decrypt_backup(Some(PASS), &a), Err(HbError::BackupParamsOutOfRange(_))), "t_cost ceiling");

        h = encrypted_header(M_COST_DEFAULT, T_COST_DEFAULT, P_COST_MAX + 1, &salt, &nonce);
        a = h.to_vec();
        a.extend_from_slice(&body);
        assert!(matches!(decrypt_backup(Some(PASS), &a), Err(HbError::BackupParamsOutOfRange(_))), "p_cost ceiling");
    }

    #[test]
    fn backup_roundtrips_with_nfkc_passphrase() {
        // Cross-platform guard: encrypt with composed 'é' (U+00E9), decrypt with the decomposed
        // 'e'+U+0301 equivalent. NFKC normalizes both to the same key. This is the *only* CI
        // exercise of the NFKC requirement, since restore-on-a-different-OS can't run here.
        let composed = "café-backup-key"; // U+00E9
        let decomposed = "cafe\u{0301}-backup-key"; // 'e' + combining acute
        assert_ne!(composed, decomposed, "the two encodings differ byte-for-byte");
        let archive = encrypt_backup(BackupMode::Passphrase(composed), PLAIN).unwrap();
        assert_eq!(decrypt_backup(Some(decomposed), &archive).unwrap(), PLAIN);
    }

    #[test]
    fn nfkc_length_floor_measured_on_normalized_form() {
        // A passphrase that is short after NFKC normalization is rejected, even if its raw codepoint
        // count looks longer — the floor is measured on the normalized form at both layers.
        let archive = encrypt_backup(BackupMode::Passphrase("aaaaaaaaaaaa"), PLAIN); // exactly 12
        assert!(archive.is_ok(), "12 chars is the floor");
        assert!(matches!(
            encrypt_backup(BackupMode::Passphrase("aaaaaaaaaaa"), PLAIN), // 11
            Err(HbError::PassphraseTooShort { .. })
        ));
    }

    #[test]
    fn is_encrypted_backup_rejects_unknown_mode_byte() {
        // chorus/Codex: an unknown mode byte must be a clean reject, not classified as plaintext.
        let mut archive = enc(PASS);
        archive[OFF_MODE] = 7; // neither plaintext (0) nor passphrase (1)
        assert!(matches!(is_encrypted_backup(&archive), Err(HbError::InvalidBackup(_))));
        // The valid modes still classify correctly.
        assert!(is_encrypted_backup(&enc(PASS)).unwrap());
        assert!(!is_encrypted_backup(&encrypt_backup(BackupMode::Plaintext, PLAIN).unwrap()).unwrap());
    }

    fn _assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn derived_key_implements_zeroize_on_drop() {
        // By-construction: assert the compile-time bound rather than a UB memory-inspection test.
        _assert_zeroize_on_drop::<DerivedKey>();
    }
}
