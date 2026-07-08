//! Keystore: `<home>/identity/keys.json` + `<home>/identity/card.txt` (spec §Data Model,
//! DESIGN.md §2/§7).
//!
//! M0 ships the **0600-file fallback** everywhere: private keys in a mode-0600 JSON file inside a
//! mode-0700 directory (Unix; on Windows the profile ACL is the floor for now). Platform
//! encryption at rest — DPAPI (port of Hoardbook's `hb-dpapi`) / Secret Service — is the M6
//! hardening milestone; the file format below is what those wrap, so nothing here changes shape.
//!
//! Writes are atomic (temp file + rename): a crash mid-rotate leaves the old identity intact,
//! never a half-written keystore.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::card::Card;
use crate::error::CoreError;
use crate::identity::Identity;

pub const KEYS_FILE: &str = "keys.json";
pub const CARD_FILE: &str = "card.txt";

/// The Mascara home directory: `$MASCARA_HOME` if set (tests, portable installs), else
/// `~/.mascara` (spec §Data Model).
pub fn default_home() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MASCARA_HOME") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    dirs::home_dir().map(|h| h.join(".mascara"))
}

/// On-disk shape of `keys.json`. `v` is the schema discriminant; secrets are hex so the file is
/// inspectable when a human must recover by hand.
#[derive(Serialize, Deserialize)]
struct KeysFile {
    v: u8,
    transport_sk: String,
    sealing_sk: String,
    created_at: String,
}

fn identity_dir(home: &Path) -> PathBuf {
    home.join("identity")
}

/// Load the identity, or mint-and-save one if none exists yet. Returns `(identity, created)`.
pub fn init_if_missing(home: &Path) -> Result<(Identity, bool), CoreError> {
    match load_identity(home) {
        Ok(id) => Ok((id, false)),
        Err(CoreError::NoIdentity(_)) => {
            let id = Identity::mint();
            save_identity(home, &id)?;
            Ok((id, true))
        }
        Err(e) => Err(e),
    }
}

pub fn load_identity(home: &Path) -> Result<Identity, CoreError> {
    let path = identity_dir(home).join(KEYS_FILE);
    if !path.is_file() {
        return Err(CoreError::NoIdentity(path.display().to_string()));
    }
    let raw = Zeroizing::new(fs::read_to_string(&path)?);
    let parsed: KeysFile = serde_json::from_str(&raw)?;
    if parsed.v != 1 {
        return Err(CoreError::Keystore(format!(
            "unsupported keys.json version {} (this Mascara understands v1)",
            parsed.v
        )));
    }
    let transport = decode_secret(&parsed.transport_sk, "transport_sk")?;
    let sealing = decode_secret(&parsed.sealing_sk, "sealing_sk")?;
    let id = Identity::from_secret_bytes(&transport, &sealing);
    // KeysFile still holds the hex secrets; scrub them before drop.
    let mut parsed = parsed;
    parsed.transport_sk.zeroize();
    parsed.sealing_sk.zeroize();
    Ok(id)
}

/// Persist the identity (keys.json, 0600) and its public card (card.txt) atomically.
pub fn save_identity(home: &Path, id: &Identity) -> Result<(), CoreError> {
    let dir = identity_dir(home);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }

    let mut transport_hex = hex::encode(id.transport_secret_bytes());
    let mut sealing_hex = hex::encode(id.sealing_secret_bytes());
    let file = KeysFile {
        v: 1,
        transport_sk: transport_hex.clone(),
        sealing_sk: sealing_hex.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let json = Zeroizing::new(serde_json::to_string_pretty(&file)?);
    transport_hex.zeroize();
    sealing_hex.zeroize();
    drop(file); // its hex copies are re-derivable from `id`; scrubbed best-effort via the locals above

    atomic_write(&dir.join(KEYS_FILE), json.as_bytes(), true)?;
    write_card(home, &id.card())?;
    Ok(())
}

/// Rewrite `card.txt` from the (public) card. Not secret — world-readable is fine.
pub fn write_card(home: &Path, card: &Card) -> Result<PathBuf, CoreError> {
    let dir = identity_dir(home);
    fs::create_dir_all(&dir)?;
    let path = dir.join(CARD_FILE);
    atomic_write(&path, format!("{}\n", card.encode()).as_bytes(), false)?;
    Ok(path)
}

/// Mint a fresh identity and overwrite the stored one. **Rotation invalidates the old card and
/// every ticket sealed to the old keys** (spec D3) — the caller (CLI/GUI) owns showing that
/// warning *before* calling this; there is no undo.
pub fn rotate(home: &Path) -> Result<Identity, CoreError> {
    let id = Identity::mint();
    save_identity(home, &id)?;
    Ok(id)
}

fn decode_secret(hex_str: &str, field: &str) -> Result<[u8; 32], CoreError> {
    let bytes = Zeroizing::new(
        hex::decode(hex_str)
            .map_err(|e| CoreError::Keystore(format!("bad hex in {field}: {e}")))?,
    );
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Keystore(format!("{field} is not 32 bytes")))?;
    Ok(arr)
}

/// Write via temp file + rename so a crash never leaves a torn file. `private` sets 0600 before
/// any secret byte lands on disk (Unix).
fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> Result<(), CoreError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        let _ = private;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_mints_then_reloads_same_identity() {
        let home = tempfile::tempdir().unwrap();
        let (id, created) = init_if_missing(home.path()).unwrap();
        assert!(created);
        let (again, created2) = init_if_missing(home.path()).unwrap();
        assert!(!created2);
        assert_eq!(id.card(), again.card());
    }

    #[test]
    fn card_file_matches_identity() {
        let home = tempfile::tempdir().unwrap();
        let (id, _) = init_if_missing(home.path()).unwrap();
        let on_disk = fs::read_to_string(home.path().join("identity").join(CARD_FILE)).unwrap();
        assert_eq!(on_disk.trim(), id.card().encode());
    }

    #[test]
    fn rotate_changes_keys_and_card_file() {
        let home = tempfile::tempdir().unwrap();
        let (old, _) = init_if_missing(home.path()).unwrap();
        let new = rotate(home.path()).unwrap();
        assert_ne!(old.card(), new.card(), "rotation must mint fresh keys");
        // The reloaded identity and the on-disk card are both the NEW ones.
        assert_eq!(load_identity(home.path()).unwrap().card(), new.card());
        let on_disk = fs::read_to_string(home.path().join("identity").join(CARD_FILE)).unwrap();
        assert_eq!(on_disk.trim(), new.card().encode());
    }

    #[test]
    fn missing_identity_is_a_reasoned_error() {
        let home = tempfile::tempdir().unwrap();
        // Identity intentionally has no Debug (it holds secrets), so match without formatting it.
        match load_identity(home.path()) {
            Err(CoreError::NoIdentity(_)) => {}
            Err(other) => panic!("expected NoIdentity, got a different error: {other}"),
            Ok(_) => panic!("expected NoIdentity, got an identity"),
        }
    }

    #[test]
    fn corrupt_keys_file_is_a_reasoned_error() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("identity");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(KEYS_FILE), b"{not json").unwrap();
        assert!(matches!(load_identity(home.path()), Err(CoreError::Json(_))));
    }

    #[cfg(unix)]
    #[test]
    fn keys_file_is_0600_and_dir_0700() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        init_if_missing(home.path()).unwrap();
        let dir = home.path().join("identity");
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let keys = dir.join(KEYS_FILE);
        assert_eq!(fs::metadata(&keys).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
