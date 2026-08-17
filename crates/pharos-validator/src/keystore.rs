//! EIP-2335 BLS keystore decryption.
//!
//! Supports:
//! - KDF: `scrypt` or `pbkdf2` (HMAC-SHA256)
//! - Cipher: `aes-128-ctr`
//! - Checksum: `sha256`
//!
//! Passwords are NFKD-normalized per EIP-2335 §Password Requirements.
//!
//! Spec: <https://eips.ethereum.org/EIPS/eip-2335>

use std::path::Path;

use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use scrypt::{Params as ScryptParams, scrypt};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;

use pharos_utils::bls::{BLSSecretKey, BlsError};

/// Error type for keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported KDF: {0}")]
    UnsupportedKdf(String),

    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("unsupported checksum function: {0}")]
    UnsupportedChecksum(String),

    #[error("checksum mismatch — wrong password or corrupted keystore")]
    ChecksumMismatch,

    #[error("invalid hex in keystore field '{0}': {1}")]
    HexDecode(String, String),

    #[error("scrypt error: {0}")]
    Scrypt(String),

    #[error("pbkdf2 error: {0}")]
    Pbkdf2(String),

    #[error("invalid scrypt parameters")]
    InvalidScryptParams,

    #[error("invalid AES-CTR IV length (expected 16 bytes)")]
    InvalidIvLength,

    #[error("invalid decryption key length (expected 32 bytes from KDF)")]
    InvalidKeyLength,

    #[error("BLS key error: {0}")]
    Bls(#[from] BlsError),

    #[error("I/O error reading keystore: {0}")]
    Io(#[from] std::io::Error),

    #[error("missing field '{0}' in keystore")]
    MissingField(&'static str),
}

// AES-128-CTR type alias (big-endian counter, as used by EIP-2335).
type Aes128Ctr = Ctr128BE<Aes128>;

/// Raw JSON shape of an EIP-2335 keystore.
///
/// Only the fields needed for decryption are parsed; extra fields are ignored.
#[derive(serde::Deserialize, Debug)]
pub struct Keystore {
    pub crypto: KeystoreCrypto,
    /// Optional UUID (not used for decryption, carried for logging).
    pub uuid: Option<String>,
    /// Optional pubkey hint (0x-prefixed hex, 48 bytes compressed).
    pub pubkey: Option<String>,
    /// Optional description.
    pub description: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct KeystoreCrypto {
    pub kdf: KdfModule,
    pub cipher: CipherModule,
    pub checksum: ChecksumModule,
}

#[derive(serde::Deserialize, Debug)]
pub struct KdfModule {
    pub function: String,
    pub params: serde_json::Value,
    pub message: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct CipherModule {
    pub function: String,
    pub params: CipherParams,
    pub message: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct CipherParams {
    /// Initialization vector — 0x-prefixed hex, 16 bytes.
    pub iv: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct ChecksumModule {
    pub function: String,
    /// Unused params field (EIP-2335 has `{}` here).
    #[allow(dead_code)]
    pub params: serde_json::Value,
    pub message: String,
}

/// Decode a 0x-prefixed hex field or a bare hex string.
fn decode_hex_field(field: &str, name: &'static str) -> Result<Vec<u8>, KeystoreError> {
    let s = field.strip_prefix("0x").unwrap_or(field);
    hex::decode(s).map_err(|e| KeystoreError::HexDecode(name.to_string(), e.to_string()))
}

/// Take the first 32 bytes of a derived key as the AES key, erroring if the KDF
/// produced fewer than 32 bytes (the shared tail of both KDF branches).
fn first_32(dk: &[u8]) -> Result<[u8; 32], KeystoreError> {
    if dk.len() < 32 {
        return Err(KeystoreError::InvalidKeyLength);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&dk[..32]);
    Ok(key)
}

/// Derive the 32-byte decryption key from the KDF module.
fn derive_key(kdf: &KdfModule, password: &[u8]) -> Result<[u8; 32], KeystoreError> {
    match kdf.function.as_str() {
        "scrypt" => {
            let params = &kdf.params;
            let n: u64 = params["n"]
                .as_u64()
                .ok_or(KeystoreError::InvalidScryptParams)?;
            let r: u32 = params["r"]
                .as_u64()
                .ok_or(KeystoreError::InvalidScryptParams)? as u32;
            let p: u32 = params["p"]
                .as_u64()
                .ok_or(KeystoreError::InvalidScryptParams)? as u32;
            let dklen: usize = params["dklen"]
                .as_u64()
                .ok_or(KeystoreError::InvalidScryptParams)? as usize;
            let salt_hex = params["salt"]
                .as_str()
                .ok_or(KeystoreError::InvalidScryptParams)?;
            let salt = decode_hex_field(salt_hex, "kdf.params.salt")?;

            // scrypt requires N to be a power of two. Validate explicitly to
            // avoid float precision risk, then derive log2(N) via trailing_zeros.
            if n == 0 || (n & (n - 1)) != 0 {
                return Err(KeystoreError::InvalidScryptParams);
            }
            let log_n = n.trailing_zeros() as u8;
            let scrypt_params =
                ScryptParams::new(log_n, r, p).map_err(|e| KeystoreError::Scrypt(e.to_string()))?;

            let mut dk = vec![0u8; dklen];
            scrypt(password, &salt, &scrypt_params, &mut dk)
                .map_err(|e| KeystoreError::Scrypt(e.to_string()))?;

            first_32(&dk)
        }
        "pbkdf2" => {
            let params = &kdf.params;
            let dklen: usize = params["dklen"]
                .as_u64()
                .ok_or(KeystoreError::MissingField("kdf.params.dklen"))?
                as usize;
            let c: u32 = params["c"]
                .as_u64()
                .ok_or(KeystoreError::MissingField("kdf.params.c"))?
                as u32;
            let salt_hex = params["salt"]
                .as_str()
                .ok_or(KeystoreError::MissingField("kdf.params.salt"))?;
            let salt = decode_hex_field(salt_hex, "kdf.params.salt")?;

            let prf = params["prf"].as_str().unwrap_or("hmac-sha256");
            if prf != "hmac-sha256" {
                return Err(KeystoreError::UnsupportedKdf(format!("pbkdf2 prf: {prf}")));
            }

            let mut dk = vec![0u8; dklen];
            pbkdf2::<Hmac<Sha256>>(password, &salt, c, &mut dk)
                .map_err(|e| KeystoreError::Pbkdf2(e.to_string()))?;

            first_32(&dk)
        }
        other => Err(KeystoreError::UnsupportedKdf(other.to_string())),
    }
}

/// Decrypt an EIP-2335 keystore and return the `BLSSecretKey`.
///
/// The `password` is NFKD-normalized before use per EIP-2335 §Password Requirements.
pub fn decrypt_keystore(
    keystore: &Keystore,
    password: &str,
) -> Result<BLSSecretKey, KeystoreError> {
    // Step 1: NFKD-normalize the password.
    let normalized_password: String = password.nfkd().collect();
    let password_bytes = normalized_password.as_bytes();

    // Step 2: Derive the decryption key via KDF.
    let dk = derive_key(&keystore.crypto.kdf, password_bytes)?;

    // Step 3: Verify checksum — SHA256(dk[16..32] || cipher.message).
    let checksum_fn = keystore.crypto.checksum.function.as_str();
    if checksum_fn != "sha256" {
        return Err(KeystoreError::UnsupportedChecksum(checksum_fn.to_string()));
    }
    let cipher_msg = decode_hex_field(&keystore.crypto.cipher.message, "cipher.message")?;
    let mut hasher = Sha256::new();
    hasher.update(&dk[16..32]);
    hasher.update(&cipher_msg);
    let computed_checksum = hasher.finalize();

    let expected_checksum =
        decode_hex_field(&keystore.crypto.checksum.message, "checksum.message")?;
    // Constant-time compare for defense-in-depth: the checksum gates a
    // password-derived decryption key, so a variable-time `!=` is a (weak,
    // offline-only) oracle distinguishing correct vs wrong passwords.
    if !bool::from(
        computed_checksum
            .as_slice()
            .ct_eq(expected_checksum.as_slice()),
    ) {
        return Err(KeystoreError::ChecksumMismatch);
    }

    // Step 4: Decrypt the secret key using AES-128-CTR.
    let cipher_fn = keystore.crypto.cipher.function.as_str();
    if cipher_fn != "aes-128-ctr" {
        return Err(KeystoreError::UnsupportedCipher(cipher_fn.to_string()));
    }
    let iv_bytes = decode_hex_field(&keystore.crypto.cipher.params.iv, "cipher.params.iv")?;
    if iv_bytes.len() != 16 {
        return Err(KeystoreError::InvalidIvLength);
    }
    let iv: [u8; 16] = iv_bytes.try_into().expect("length checked");
    let aes_key: [u8; 16] = dk[..16].try_into().expect("dk is 32 bytes");

    let mut plaintext = cipher_msg.clone();
    let mut cipher = Aes128Ctr::new(&aes_key.into(), &iv.into());
    cipher.apply_keystream(&mut plaintext);

    // Step 5: Deserialize as a 32-byte BLS scalar.
    if plaintext.len() != 32 {
        return Err(KeystoreError::Bls(
            pharos_utils::bls::BlsError::InvalidSecretKey,
        ));
    }
    let key_bytes: [u8; 32] = plaintext.try_into().expect("length checked");
    BLSSecretKey::from_bytes(&key_bytes).map_err(KeystoreError::Bls)
}

/// Load a keystore from a JSON file and decrypt it with the given password.
pub fn load_keystore_file(
    keystore_path: &Path,
    password: &str,
) -> Result<BLSSecretKey, KeystoreError> {
    let json = std::fs::read_to_string(keystore_path)?;
    let keystore: Keystore = serde_json::from_str(&json)?;
    decrypt_keystore(&keystore, password)
}

/// Load all keystores from `keystore_dir`, pairing each with the password
/// found at `secrets_dir/<uuid>` (or `secrets_dir/<pubkey>` as fallback).
///
/// Returns `(pubkey_hex, secret_key)` pairs for all successfully loaded keystores.
/// Errors for individual keystores are logged and skipped; if you need all-or-nothing
/// behaviour, iterate the result and check for missing expected keys.
pub fn load_all_keystores(keystore_dir: &Path, secrets_dir: &Path) -> Vec<(String, BLSSecretKey)> {
    let mut loaded = Vec::new();
    let entries = match std::fs::read_dir(keystore_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(dir = %keystore_dir.display(), "cannot read keystore dir: {e}");
            return loaded;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let json = match std::fs::read_to_string(&path) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(path = %path.display(), "cannot read keystore: {e}");
                continue;
            }
        };
        let ks: Keystore = match serde_json::from_str(&json) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(path = %path.display(), "cannot parse keystore JSON: {e}");
                continue;
            }
        };

        // Determine the password file. Different tools name the secret file
        // differently, so try every known convention and use the first that
        // EXISTS (not merely the first `Some`): `<uuid>`, `<pubkey-no-0x>`,
        // `0x<pubkey>` (the common CL client layout), and the keystore filename stem.
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let password_file = {
            let pubkey_no_0x = ks
                .pubkey
                .as_deref()
                .map(|p| secrets_dir.join(p.strip_prefix("0x").unwrap_or(p)));
            let pubkey_0x = ks.pubkey.as_deref().map(|p| {
                let with_0x = if p.starts_with("0x") {
                    p.to_string()
                } else {
                    format!("0x{p}")
                };
                secrets_dir.join(with_0x)
            });
            let candidates = [
                ks.uuid.as_deref().map(|u| secrets_dir.join(u)),
                pubkey_no_0x,
                pubkey_0x,
                Some(secrets_dir.join(&stem)),
            ];
            candidates
                .into_iter()
                .flatten()
                .find(|p| p.exists())
                .unwrap_or_else(|| secrets_dir.join(&stem))
        };

        let password = match std::fs::read_to_string(&password_file) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    password_file = %password_file.display(),
                    "cannot read password file: {e}"
                );
                continue;
            }
        };
        // Trim trailing newline from password file (common editor artifact).
        let password = password.trim_end_matches(['\n', '\r']).to_string();

        match decrypt_keystore(&ks, &password) {
            Ok(sk) => {
                let pubkey_hex = format!("0x{}", hex::encode(sk.to_pubkey().as_ref()));
                tracing::info!(pubkey = %pubkey_hex, "loaded keystore");
                loaded.push((pubkey_hex, sk));
            }
            Err(e) => {
                tracing::error!(path = %path.display(), "keystore decrypt failed: {e}");
            }
        }
    }

    loaded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-2335 scrypt test vector.
    ///
    /// Source: https://eips.ethereum.org/EIPS/eip-2335 (Scrypt Test Vector)
    /// Retrieved 2026-06-05 from the live EIP page.
    /// Password (before NFKD): `𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑`
    /// Encoded password (NFKD UTF-8): `0x7465737470617373776f7264f09f9491`
    /// Expected secret (hex): `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`
    const SCRYPT_KEYSTORE_JSON: &str = r#"{
      "crypto": {
        "kdf": {
          "function": "scrypt",
          "params": {
            "dklen": 32,
            "n": 262144,
            "p": 1,
            "r": 8,
            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
          },
          "message": ""
        },
        "checksum": {
          "function": "sha256",
          "params": {},
          "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
        },
        "cipher": {
          "function": "aes-128-ctr",
          "params": {
            "iv": "264daa3f303d7259501c93d997d84fe6"
          },
          "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
        }
      },
      "description": "This is a test keystore that uses scrypt to secure the secret.",
      "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
      "path": "m/12381/60/3141592653/589793238",
      "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
      "version": 4
    }"#;

    const SCRYPT_PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
    const SCRYPT_EXPECTED_SECRET_HEX: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    /// EIP-2335 pbkdf2 test vector.
    ///
    /// Source: https://eips.ethereum.org/EIPS/eip-2335 (PBKDF2 Test Vector)
    /// Retrieved 2026-06-05 from the live EIP page.
    /// Same password, same expected secret as the scrypt vector.
    /// Verified: Python `hashlib.pbkdf2_hmac('sha256', pw, salt, 262144, 32)` produces
    /// dk = ff9f053388ab9bd50720ee50a6a8281a940f3f49c1b7e7bafe2e9042c01d319a;
    /// SHA256(dk[16:32] || cipher_msg) = 8a9f5d9912...febf1 (matches spec).
    const PBKDF2_KEYSTORE_JSON: &str = r#"{
      "crypto": {
        "kdf": {
          "function": "pbkdf2",
          "params": {
            "dklen": 32,
            "c": 262144,
            "prf": "hmac-sha256",
            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
          },
          "message": ""
        },
        "checksum": {
          "function": "sha256",
          "params": {},
          "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
        },
        "cipher": {
          "function": "aes-128-ctr",
          "params": {
            "iv": "264daa3f303d7259501c93d997d84fe6"
          },
          "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
        }
      },
      "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
      "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
      "path": "m/12381/60/0/0",
      "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
      "version": 4
    }"#;

    #[test]
    fn scrypt_decryption_matches_eip2335_test_vector() {
        let ks: Keystore =
            serde_json::from_str(SCRYPT_KEYSTORE_JSON).expect("parse scrypt keystore");
        let sk = decrypt_keystore(&ks, SCRYPT_PASSWORD).expect("decrypt scrypt keystore");
        let secret_bytes = sk.to_bytes();
        let hex_out = hex::encode(secret_bytes);
        assert_eq!(
            hex_out, SCRYPT_EXPECTED_SECRET_HEX,
            "scrypt decryption must match EIP-2335 test vector"
        );
    }

    #[test]
    fn pbkdf2_decryption_matches_eip2335_test_vector() {
        let ks: Keystore =
            serde_json::from_str(PBKDF2_KEYSTORE_JSON).expect("parse pbkdf2 keystore");
        let sk = decrypt_keystore(&ks, SCRYPT_PASSWORD).expect("decrypt pbkdf2 keystore");
        let secret_bytes = sk.to_bytes();
        let hex_out = hex::encode(secret_bytes);
        assert_eq!(
            hex_out, SCRYPT_EXPECTED_SECRET_HEX,
            "pbkdf2 decryption must match EIP-2335 test vector"
        );
    }

    #[test]
    fn wrong_password_returns_checksum_mismatch() {
        let ks: Keystore =
            serde_json::from_str(SCRYPT_KEYSTORE_JSON).expect("parse scrypt keystore");
        let result = decrypt_keystore(&ks, "wrong_password");
        let err = match result {
            Ok(_) => panic!("must fail with wrong password"),
            Err(e) => e,
        };
        assert!(
            matches!(err, KeystoreError::ChecksumMismatch),
            "expected ChecksumMismatch, got: {err}"
        );
    }

    #[test]
    fn nfkd_normalization_applied() {
        // The same unicode string in different normalization forms must decrypt
        // to the same key, because we NFKD-normalize before use.
        let ks: Keystore =
            serde_json::from_str(SCRYPT_KEYSTORE_JSON).expect("parse scrypt keystore");
        // The password is already the fraktur form; NFC or NFD of the same
        // codepoints should produce the same NFKD bytes.
        // We just verify the happy path goes through.
        let sk = decrypt_keystore(&ks, SCRYPT_PASSWORD).expect("decrypt must succeed");
        let _ = sk.to_pubkey();
    }

    #[test]
    fn scrypt_non_power_of_two_n_returns_invalid_params() {
        // Build a keystore JSON with n=3 (not a power of two).
        let bad_n_json = r#"{
          "crypto": {
            "kdf": {
              "function": "scrypt",
              "params": {
                "dklen": 32,
                "n": 3,
                "p": 1,
                "r": 8,
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
              },
              "message": ""
            },
            "checksum": {
              "function": "sha256",
              "params": {},
              "message": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "cipher": {
              "function": "aes-128-ctr",
              "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
              "message": "0000000000000000000000000000000000000000000000000000000000000000"
            }
          },
          "uuid": "00000000-0000-0000-0000-000000000000"
        }"#;
        let ks: Keystore = serde_json::from_str(bad_n_json).expect("parse keystore");
        let err = match decrypt_keystore(&ks, "any") {
            Ok(_) => panic!("non-power-of-2 N must fail"),
            Err(e) => e,
        };
        assert!(
            matches!(err, KeystoreError::InvalidScryptParams),
            "expected InvalidScryptParams, got: {err}"
        );
    }

    #[test]
    fn scrypt_zero_n_returns_invalid_params() {
        let bad_n_json = r#"{
          "crypto": {
            "kdf": {
              "function": "scrypt",
              "params": {
                "dklen": 32,
                "n": 0,
                "p": 1,
                "r": 8,
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
              },
              "message": ""
            },
            "checksum": {
              "function": "sha256",
              "params": {},
              "message": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "cipher": {
              "function": "aes-128-ctr",
              "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
              "message": "0000000000000000000000000000000000000000000000000000000000000000"
            }
          },
          "uuid": "00000000-0000-0000-0000-000000000000"
        }"#;
        let ks: Keystore = serde_json::from_str(bad_n_json).expect("parse keystore");
        let err = match decrypt_keystore(&ks, "any") {
            Ok(_) => panic!("zero N must fail"),
            Err(e) => e,
        };
        assert!(
            matches!(err, KeystoreError::InvalidScryptParams),
            "expected InvalidScryptParams, got: {err}"
        );
    }
}
