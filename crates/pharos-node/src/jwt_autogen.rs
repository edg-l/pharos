//! Auto-generation and reuse of the Engine API JWT secret file.
//!
//! Per `execution-apis/src/engine/authentication.md`: if `--jwt-secret` is
//! not given, the CL SHOULD generate a 32-byte secret, persist it as a
//! hex-encoded `jwt.hex` file, and use it for the duration of the run.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use tracing::info;
#[cfg(not(unix))]
use tracing::warn;

use pharos_engine::{JwtSecret, load_jwt_secret};

/// Return a `JwtSecret`, sourcing it by one of three paths:
///
/// 1. If `explicit` is `Some(path)`, load from that path (user-supplied
///    `--jwt-secret`).
/// 2. If `<data_dir>/jwt.hex` already exists, reload it (across restarts).
/// 3. Otherwise, generate 32 random bytes, write them as 64 lowercase hex
///    chars to `<data_dir>/jwt.hex` (mode 0o600 on Unix), then reload.
pub fn ensure_jwt_secret(data_dir: &Path, explicit: Option<&Path>) -> anyhow::Result<JwtSecret> {
    if let Some(path) = explicit {
        return load_jwt_secret(path)
            .with_context(|| format!("loading JWT secret from {}", path.display()));
    }

    let jwt_path: PathBuf = data_dir.join("jwt.hex");

    if jwt_path.exists() {
        let secret = load_jwt_secret(&jwt_path)
            .with_context(|| format!("loading JWT secret from {}", jwt_path.display()))?;
        info!(path = %jwt_path.display(), "reusing existing jwt.hex");
        return Ok(secret);
    }

    // Generate a fresh secret.
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("OS RNG failed: {e}"))?;

    let hex_secret = hex::encode(buf);

    {
        let mut file = open_for_write(&jwt_path)?;
        file.write_all(hex_secret.as_bytes())
            .with_context(|| format!("writing jwt.hex to {}", jwt_path.display()))?;
    }

    info!(path = %jwt_path.display(), "generated jwt.hex");

    load_jwt_secret(&jwt_path)
        .with_context(|| format!("reloading generated jwt.hex from {}", jwt_path.display()))
}

#[cfg(unix)]
fn open_for_write(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating jwt.hex at {}", path.display()))
}

#[cfg(not(unix))]
fn open_for_write(path: &Path) -> anyhow::Result<std::fs::File> {
    warn!(
        path = %path.display(),
        "non-Unix platform: jwt.hex created without restricted permissions"
    );
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating jwt.hex at {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::SystemTime;

    use tempfile::TempDir;

    use super::*;

    /// Write a known 32-byte secret as 64 hex chars to `path`.
    fn write_known_secret(path: &Path, bytes: &[u8; 32]) {
        fs::write(path, hex::encode(bytes)).unwrap();
    }

    /// (a) When an explicit path is given, load and return that secret.
    #[test]
    fn explicit_path_wins() {
        let dir = TempDir::new().unwrap();
        let secret_path = dir.path().join("my_secret.hex");
        let known: [u8; 32] = [0xAB; 32];
        write_known_secret(&secret_path, &known);

        let result = ensure_jwt_secret(dir.path(), Some(&secret_path)).unwrap();
        assert_eq!(result.as_bytes(), &known);
    }

    /// (b) When no explicit path and no jwt.hex exists, generate one.
    #[test]
    fn generates_on_missing() {
        let dir = TempDir::new().unwrap();
        let jwt_path = dir.path().join("jwt.hex");

        assert!(!jwt_path.exists(), "precondition: jwt.hex must not exist");

        let result = ensure_jwt_secret(dir.path(), None).unwrap();

        assert!(jwt_path.exists(), "jwt.hex was not created");
        let contents = fs::read_to_string(&jwt_path).unwrap();
        assert_eq!(
            contents.len(),
            64,
            "expected 64 hex chars, got {}",
            contents.len()
        );
        assert!(
            contents.chars().all(|c| c.is_ascii_hexdigit()),
            "jwt.hex contents are not hex: {contents}"
        );
        // The returned secret must match the file.
        let loaded = load_jwt_secret(&jwt_path).unwrap();
        assert_eq!(result.as_bytes(), loaded.as_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&jwt_path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "jwt.hex mode should be 0o600, got 0o{:o}",
                mode & 0o777
            );
        }
    }

    /// (c) When jwt.hex already exists, reuse it without overwriting.
    #[test]
    fn reuses_on_existing() {
        let dir = TempDir::new().unwrap();
        let jwt_path = dir.path().join("jwt.hex");
        let known: [u8; 32] = [0x5C; 32];
        write_known_secret(&jwt_path, &known);

        let mtime_before = fs::metadata(&jwt_path)
            .unwrap()
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let result = ensure_jwt_secret(dir.path(), None).unwrap();

        assert_eq!(
            result.as_bytes(),
            &known,
            "returned secret does not match pre-written value"
        );

        let mtime_after = fs::metadata(&jwt_path)
            .unwrap()
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let delta = match mtime_after.duration_since(mtime_before) {
            Ok(d) => d,
            Err(e) => e.duration(), // mtime moved backward — also indicates a rewrite
        };
        assert!(
            delta.as_secs() < 1,
            "jwt.hex mtime changed (file was rewritten)"
        );
    }
}
