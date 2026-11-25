// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! Passphrase-sealed local storage for the terminal client.
//!
//! A terminal machine has no Keychain or Secure Enclave, so every secret the
//! client keeps (the Ed25519 identity seed, the core checkpoint that holds the
//! Olm ratchets, and the message history) is sealed with XChaCha20-Poly1305
//! under a 32-byte key stretched from the user's passphrase with Argon2id. Only
//! the KDF parameters and salt are stored in the clear.
//!
//! Each sealed file binds its purpose label as associated data, so one file
//! can never be substituted for another. Writes go to a temporary file that is
//! fsynced and then renamed over the target, so a crash leaves either the old
//! or the new generation readable, never a torn one.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const HEADER_FILE: &str = "vault.json";
const LOCK_FILE: &str = "vault.lock";
const SEALED_MAGIC: &[u8; 4] = b"PGV1";
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Domain separation for every sealed file's associated data.
const AAD_PREFIX: &str = "pigeon-cli.vault.v1:";

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    /// The passphrase did not open the vault, or a sealed file was tampered with.
    Unseal,
    Corrupt(&'static str),
    AlreadyExists,
    NotInitialized,
    /// Another Pigeon process holds the vault. Two writers would fork the
    /// ratchet state, so this is a hard stop rather than a wait.
    Busy,
    Kdf,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage error: {error}"),
            Self::Unseal => f.write_str("wrong passphrase or tampered vault"),
            Self::Corrupt(what) => write!(f, "vault file is corrupt: {what}"),
            Self::AlreadyExists => f.write_str("a Pigeon identity already exists here"),
            Self::NotInitialized => f.write_str("no Pigeon identity here; run `pigeon init` first"),
            Self::Busy => f.write_str("another Pigeon process is using this vault"),
            Self::Kdf => f.write_str("passphrase key derivation failed"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    version: u32,
    kdf: String,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

/// KDF cost. Interactive-grade Argon2id (64 MiB, 3 passes) by default; tests
/// use a cheap profile so the suite stays fast.
#[derive(Clone, Copy, Debug)]
pub struct KdfCost {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfCost {
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

pub struct Vault {
    dir: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    /// Held for the life of the vault; the OS releases the lock if we crash.
    _lock: File,
}

impl Vault {
    pub fn exists(dir: &Path) -> bool {
        dir.join(HEADER_FILE).is_file()
    }

    /// Creates a fresh vault. Fails if one already exists so an identity is
    /// never silently replaced.
    pub fn create(dir: &Path, passphrase: &str, cost: KdfCost) -> Result<Self, VaultError> {
        if Self::exists(dir) {
            return Err(VaultError::AlreadyExists);
        }
        create_private_dir(dir)?;
        let lock = acquire_lock(dir)?;
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|_| VaultError::Kdf)?;
        let header = Header {
            version: 1,
            kdf: "argon2id".into(),
            m_cost_kib: cost.m_cost_kib,
            t_cost: cost.t_cost,
            p_cost: cost.p_cost,
            salt: hex::encode(salt),
        };
        let key = derive_key(passphrase, &header)?;
        let bytes =
            serde_json::to_vec_pretty(&header).map_err(|_| VaultError::Corrupt("header"))?;
        write_atomic(&dir.join(HEADER_FILE), &bytes)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            key,
            _lock: lock,
        })
    }

    /// Opens an existing vault. The passphrase is checked by the caller's first
    /// `open` of a sealed file (AEAD failure means a wrong passphrase).
    pub fn open(dir: &Path, passphrase: &str) -> Result<Self, VaultError> {
        if !Self::exists(dir) {
            return Err(VaultError::NotInitialized);
        }
        let lock = acquire_lock(dir)?;
        let bytes = fs::read(dir.join(HEADER_FILE))?;
        let header: Header =
            serde_json::from_slice(&bytes).map_err(|_| VaultError::Corrupt("header"))?;
        if header.version != 1 || header.kdf != "argon2id" {
            return Err(VaultError::Corrupt("unsupported vault version"));
        }
        let key = derive_key(passphrase, &header)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            key,
            _lock: lock,
        })
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Seals `plaintext` under `label` and durably replaces `<label>.sealed`.
    pub fn store(&self, label: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        let sealed = self.seal(label, plaintext)?;
        write_atomic(&self.path(label), &sealed)
    }

    /// Reads and authenticates `<label>.sealed`; `None` if it does not exist.
    pub fn load(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let bytes = match fs::read(self.path(label)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        self.unseal(label, &bytes).map(Some)
    }

    fn path(&self, label: &str) -> PathBuf {
        self.dir.join(format!("{label}.sealed"))
    }

    fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Kdf)?;
        let aad = format!("{AAD_PREFIX}{label}");
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| VaultError::Unseal)?;
        let mut out = Vec::with_capacity(4 + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(SEALED_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if sealed.len() < 4 + NONCE_LEN || &sealed[..4] != SEALED_MAGIC {
            return Err(VaultError::Corrupt("sealed file header"));
        }
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let aad = format!("{AAD_PREFIX}{label}");
        cipher
            .decrypt(
                XNonce::from_slice(&sealed[4..4 + NONCE_LEN]),
                Payload {
                    msg: &sealed[4 + NONCE_LEN..],
                    aad: aad.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| VaultError::Unseal)
    }
}

fn derive_key(passphrase: &str, header: &Header) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let salt = hex::decode(&header.salt).map_err(|_| VaultError::Corrupt("salt"))?;
    if salt.len() != SALT_LEN {
        return Err(VaultError::Corrupt("salt"));
    }
    let params = Params::new(
        header.m_cost_kib,
        header.t_cost,
        header.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::Corrupt("kdf parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
        .map_err(|_| VaultError::Kdf)?;
    Ok(key)
}

fn acquire_lock(dir: &Path) -> Result<File, VaultError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_FILE))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(VaultError::Busy),
        Err(fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

fn create_private_dir(dir: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes `bytes` to a sibling temp file, fsyncs it, renames it over `path`,
/// then fsyncs the directory so the rename itself is durable.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) const TEST_COST: KdfCost = KdfCost {
    m_cost_kib: 256,
    t_cost: 1,
    p_cost: 1,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        {
            let vault = Vault::create(dir.path(), "correct horse", TEST_COST).unwrap();
            vault.store("identity", b"seed bytes").unwrap();
            assert_eq!(&**vault.load("identity").unwrap().unwrap(), b"seed bytes");
            assert!(vault.load("missing").unwrap().is_none());
        }
        let wrong = Vault::open(dir.path(), "battery staple").unwrap();
        assert!(matches!(wrong.load("identity"), Err(VaultError::Unseal)));
    }

    #[test]
    fn a_sealed_file_cannot_stand_in_for_another_label() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create(dir.path(), "pw", TEST_COST).unwrap();
        vault.store("history", b"secret").unwrap();
        fs::copy(
            dir.path().join("history.sealed"),
            dir.path().join("identity.sealed"),
        )
        .unwrap();
        assert!(matches!(vault.load("identity"), Err(VaultError::Unseal)));
    }

    #[test]
    fn refuses_to_overwrite_or_share_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create(dir.path(), "pw", TEST_COST).unwrap();
        assert!(matches!(
            Vault::create(dir.path(), "pw", TEST_COST),
            Err(VaultError::AlreadyExists)
        ));
        assert!(matches!(
            Vault::open(dir.path(), "pw"),
            Err(VaultError::Busy)
        ));
        drop(vault);
        assert!(Vault::open(dir.path(), "pw").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn sealed_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create(dir.path().join("home").as_path(), "pw", TEST_COST).unwrap();
        vault.store("identity", b"x").unwrap();
        let mode = fs::metadata(vault.dir().join("identity.sealed"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(vault.dir()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }
}
