//! Master key caching with 4-hour TTL.
//!
//! Security model:
//! - Derived key encrypted with random session token (AES-256-GCM)
//! - Cache file: ~/.cache/passlock/key.cache [8B expiry][12B nonce][ciphertext]
//! - Token file: ~/.cache/passlock/token (32B random key)
//! - Both files required to recover key; either missing = re-auth

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use rand::RngCore;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_TTL_SECS: u64 = 4 * 60 * 60;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const EXPIRY_LEN: usize = 8;

fn cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("passlock"))
}

fn cache_file_path() -> Option<PathBuf> {
    cache_dir().map(|d| d.join("key.cache"))
}

fn token_file_path() -> Option<PathBuf> {
    cache_dir().map(|d| d.join("token"))
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn cache_key(derived_key: &[u8; KEY_LEN]) -> Result<(), String> {
    let cache_dir = cache_dir().ok_or("No cache directory")?;
    fs::create_dir_all(&cache_dir).map_err(|e| e.to_string())?;

    let mut token = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut token);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&token).map_err(|e| e.to_string())?;
    let encrypted_key = cipher
        .encrypt(nonce, derived_key.as_slice())
        .map_err(|e| e.to_string())?;

    let expiry = current_timestamp() + CACHE_TTL_SECS;
    let expiry_bytes = expiry.to_le_bytes();

    let cache_path = cache_file_path().ok_or("No cache file path")?;
    let mut cache_data = Vec::with_capacity(EXPIRY_LEN + NONCE_LEN + encrypted_key.len());
    cache_data.extend_from_slice(&expiry_bytes);
    cache_data.extend_from_slice(&nonce_bytes);
    cache_data.extend_from_slice(&encrypted_key);

    let mut file = fs::File::create(&cache_path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    file.write_all(&cache_data).map_err(|e| e.to_string())?;

    let token_path = token_file_path().ok_or("No token file path")?;
    let mut token_file = fs::File::create(&token_path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        token_file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    token_file.write_all(&token).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn try_cached_key() -> Option<[u8; KEY_LEN]> {
    let cache_path = cache_file_path()?;
    let token_path = token_file_path()?;

    let mut cache_file = fs::File::open(&cache_path).ok()?;
    let mut cache_data = Vec::new();
    cache_file.read_to_end(&mut cache_data).ok()?;

    if cache_data.len() < EXPIRY_LEN + NONCE_LEN {
        clear_cache();
        return None;
    }

    let expiry_bytes: [u8; 8] = cache_data[..EXPIRY_LEN].try_into().ok()?;
    let expiry = u64::from_le_bytes(expiry_bytes);

    if current_timestamp() > expiry {
        clear_cache();
        return None;
    }

    let nonce_bytes = &cache_data[EXPIRY_LEN..EXPIRY_LEN + NONCE_LEN];
    let encrypted_key = &cache_data[EXPIRY_LEN + NONCE_LEN..];

    let mut token_file = fs::File::open(&token_path).ok()?;
    let mut token = [0u8; KEY_LEN];
    if token_file.read_exact(&mut token).is_err() {
        clear_cache();
        return None;
    }

    let cipher = Aes256Gcm::new_from_slice(&token).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = cipher.decrypt(nonce, encrypted_key).ok()?;

    if decrypted.len() != KEY_LEN {
        clear_cache();
        return None;
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decrypted);
    Some(key)
}

pub fn clear_cache() {
    if let Some(cache_path) = cache_file_path() {
        fs::remove_file(cache_path).ok();
    }
    if let Some(token_path) = token_file_path() {
        fs::remove_file(token_path).ok();
    }
}
