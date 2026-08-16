//! JWT authentication for the Engine API.
//!
//! Per `execution-apis/src/engine/authentication.md`: HS256 over a 32-byte
//! shared secret, with an `iat` claim within ±60 seconds of EL clock.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

use crate::error::EngineError;

/// Shared HMAC secret used by the EL/CL to authenticate Engine API calls.
///
/// 32 bytes of raw key material, distributed via the EL/CL `jwt-secret` file.
/// Backed by `Zeroizing` so the key is wiped from the heap on drop, and the
/// `Debug` impl is redacted so the secret can never be logged.
#[derive(Clone)]
pub struct JwtSecret(zeroize::Zeroizing<Vec<u8>>);

impl JwtSecret {
    /// Construct from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes.to_vec()))
    }

    /// Raw bytes (for `EncodingKey::from_secret`).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for JwtSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JwtSecret([redacted])")
    }
}

/// Load a JWT secret from a file containing 64 hex characters (`0x`-prefix
/// allowed). Whitespace around the hex string is trimmed.
pub fn load_jwt_secret(path: &Path) -> Result<JwtSecret, EngineError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| EngineError::UnexpectedResponse(format!("read jwt secret: {e}")))?;
    let hex = raw.trim().trim_start_matches("0x");
    if hex.len() != 64 {
        return Err(EngineError::UnexpectedResponse(format!(
            "jwt secret must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| EngineError::UnexpectedResponse("jwt secret contains non-ascii".into()))?;
        bytes[i] = u8::from_str_radix(s, 16)
            .map_err(|_| EngineError::UnexpectedResponse("jwt secret is not hex".into()))?;
    }
    Ok(JwtSecret::from_bytes(bytes))
}

#[derive(Serialize)]
struct Claims {
    iat: u64,
}

/// Issue a fresh HS256 token bound to the given secret with `iat = now`.
///
/// The EL accepts `iat` within ±60 seconds, so each token is implicitly valid
/// for that window. We mint a fresh token per request rather than caching.
pub fn sign_token(secret: &JwtSecret) -> Result<String, EngineError> {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EngineError::UnexpectedResponse(format!("clock before unix epoch: {e}")))?
        .as_secs();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &Claims { iat },
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}
