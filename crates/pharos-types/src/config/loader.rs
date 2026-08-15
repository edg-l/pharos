//! YAML-based loader for [`RuntimeConfig`].
//!
//! [`load_config_dir`] accepts a path of the form
//! `<repo>/configs/<network>` (without the `.yaml` extension) and resolves:
//!
//! - `<path>.yaml` — network-level config (`GENESIS_FORK_VERSION`, fork epochs,
//!   `SLOT_DURATION_MS`, `INACTIVITY_SCORE_BIAS`, etc.). Field `PRESET_BASE`
//!   indicates which preset directory to use.
//! - `<repo>/presets/<PRESET_BASE>/phase0.yaml` — Phase 0 preset constants.
//! - `<repo>/presets/<PRESET_BASE>/altair.yaml` — Altair preset constants.
//!
//! These paths match the `~/dev/consensus-specs/` layout verbatim:
//! - `configs/mainnet.yaml`
//! - `presets/mainnet/phase0.yaml`
//! - `presets/mainnet/altair.yaml`
//!
//! ## Parsing strategy
//!
//! The consensus-specs YAML files contain fields like `TERMINAL_TOTAL_DIFFICULTY`
//! whose values exceed `u64::MAX` (e.g. `58750000000000000000000`).
//! `serde_yaml_ng` cannot represent integers larger than `u64` in its `Value`
//! enum and fails to parse the file at all when such a value is present.
//!
//! To avoid this, we use a simple line-by-line flat key-value parser. The
//! consensus-spec config/preset files are flat (no nested structures), so a
//! one-key-per-line parser is both correct and sufficient. We extract only the
//! fields we need and ignore the rest.
//!
//! ## Dimension-bearing fields
//!
//! Per `D-ethspec-yaml-loader`, the fields that drive const-generic container
//! dimensions (`SYNC_COMMITTEE_SIZE`, `VALIDATOR_REGISTRY_LIMIT`,
//! `MAX_COMMITTEES_PER_SLOT`, `MAX_VALIDATORS_PER_COMMITTEE`) are loaded and
//! returned but CANNOT be overridden at runtime without a recompile.
//! [`RuntimeConfig::assert_matches_preset`] guards this at node startup.

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use pharos_utils::{Hash256, Uint256};
use thiserror::Error;

use super::RuntimeConfig;

/// Errors produced by the YAML config loader.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// An I/O error while opening or reading a file.
    #[error("I/O error reading {file}: {source}")]
    Io {
        file: String,
        #[source]
        source: std::io::Error,
    },

    /// A required field was absent from the YAML.
    #[error("missing required config field '{0}'")]
    MissingField(&'static str),

    /// A field was present but could not be parsed as the expected type.
    #[error("invalid value for field '{field}': {value}")]
    InvalidValue { field: &'static str, value: String },
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io {
            file: String::new(),
            source: e,
        }
    }
}

/// Load a [`RuntimeConfig`] from a consensus-specs config directory path.
///
/// `path` should be the network prefix **without** the `.yaml` extension, e.g.:
/// - `~/dev/consensus-specs/configs/mainnet` (for the mainnet config)
/// - `~/dev/consensus-specs/configs/minimal` (for the minimal config)
///
/// The loader appends `.yaml` to `path` to get the network config file, then
/// reads `PRESET_BASE` from that file to locate the preset directory at
/// `<path.parent().parent()>/presets/<PRESET_BASE>/`.
pub fn load_config_dir(path: &Path) -> Result<RuntimeConfig, ConfigError> {
    // ── Step 1: load network config (<path>.yaml) ──────────────────────────
    let config_path = path.with_extension("yaml");
    let config_src = std::fs::read_to_string(&config_path).map_err(|e| ConfigError::Io {
        file: config_path.display().to_string(),
        source: e,
    })?;
    let config_map = parse_flat_yaml(&config_src);

    // Extract PRESET_BASE to locate the preset directory.
    let preset_base = config_map
        .get("PRESET_BASE")
        .ok_or(ConfigError::MissingField("PRESET_BASE"))?
        .trim_matches('\'')
        .to_string();

    // Preset directory: <grandparent_of_path>/presets/<PRESET_BASE>/
    // e.g. configs/mainnet -> configs -> consensus-specs -> presets/mainnet/
    let configs_dir = path
        .parent()
        .ok_or(ConfigError::MissingField("parent dir of config path"))?;
    let repo_root = configs_dir
        .parent()
        .ok_or(ConfigError::MissingField("repo root dir"))?;
    let preset_dir = repo_root.join("presets").join(&preset_base);

    // ── Step 2: load phase0 preset (<preset_dir>/phase0.yaml) ─────────────
    let phase0_path = preset_dir.join("phase0.yaml");
    let phase0_src = std::fs::read_to_string(&phase0_path).map_err(|e| ConfigError::Io {
        file: phase0_path.display().to_string(),
        source: e,
    })?;
    let phase0_map = parse_flat_yaml(&phase0_src);

    // ── Step 3: load altair preset (<preset_dir>/altair.yaml) ─────────────
    let altair_path = preset_dir.join("altair.yaml");
    let altair_src = std::fs::read_to_string(&altair_path).map_err(|e| ConfigError::Io {
        file: altair_path.display().to_string(),
        source: e,
    })?;
    let altair_map = parse_flat_yaml(&altair_src);

    // ── Step 3b: load bellatrix preset (<preset_dir>/bellatrix.yaml) ──────
    let bellatrix_path = preset_dir.join("bellatrix.yaml");
    let bellatrix_src = std::fs::read_to_string(&bellatrix_path).map_err(|e| ConfigError::Io {
        file: bellatrix_path.display().to_string(),
        source: e,
    })?;
    let bellatrix_map = parse_flat_yaml(&bellatrix_src);

    // ── Step 4: extract fields ─────────────────────────────────────────────

    // From network config:
    let genesis_fork_version = extract_version(&config_map, "GENESIS_FORK_VERSION")?;
    let altair_fork_version = extract_version(&config_map, "ALTAIR_FORK_VERSION")?;
    let altair_fork_epoch = extract_u64(&config_map, "ALTAIR_FORK_EPOCH")?;
    let slot_duration_ms = extract_u64(&config_map, "SLOT_DURATION_MS")?;
    let inactivity_score_bias = extract_u64(&config_map, "INACTIVITY_SCORE_BIAS")?;
    let inactivity_score_recovery_rate =
        extract_u64(&config_map, "INACTIVITY_SCORE_RECOVERY_RATE")?;
    let bellatrix_fork_version = extract_version(&config_map, "BELLATRIX_FORK_VERSION")?;
    let bellatrix_fork_epoch = extract_u64(&config_map, "BELLATRIX_FORK_EPOCH")?;
    let capella_fork_version = extract_version(&config_map, "CAPELLA_FORK_VERSION")?;
    let capella_fork_epoch = extract_u64(&config_map, "CAPELLA_FORK_EPOCH")?;
    let deposit_chain_id = extract_u64(&config_map, "DEPOSIT_CHAIN_ID")?;
    let deposit_contract_address = extract_address20(&config_map, "DEPOSIT_CONTRACT_ADDRESS")?;
    let terminal_total_difficulty = extract_uint256(&config_map, "TERMINAL_TOTAL_DIFFICULTY")?;
    let terminal_block_hash = extract_hash256(&config_map, "TERMINAL_BLOCK_HASH")?;
    let terminal_block_hash_activation_epoch =
        extract_u64(&config_map, "TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH")?;

    // From phase0 preset:
    let slots_per_epoch = extract_u64(&phase0_map, "SLOTS_PER_EPOCH")?;

    // From altair preset:
    let sync_committee_size = extract_u64(&altair_map, "SYNC_COMMITTEE_SIZE")?;
    let epochs_per_sync_committee_period =
        extract_u64(&altair_map, "EPOCHS_PER_SYNC_COMMITTEE_PERIOD")?;
    let min_sync_committee_participants =
        extract_u64(&altair_map, "MIN_SYNC_COMMITTEE_PARTICIPANTS")?;
    let update_timeout = extract_u64(&altair_map, "UPDATE_TIMEOUT")?;
    let inactivity_penalty_quotient_altair =
        extract_u64(&altair_map, "INACTIVITY_PENALTY_QUOTIENT_ALTAIR")?;
    let min_slashing_penalty_quotient_altair =
        extract_u64(&altair_map, "MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR")?;
    let proportional_slashing_multiplier_altair =
        extract_u64(&altair_map, "PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR")?;

    // From bellatrix preset:
    let inactivity_penalty_quotient_bellatrix =
        extract_u64(&bellatrix_map, "INACTIVITY_PENALTY_QUOTIENT_BELLATRIX")?;
    let min_slashing_penalty_quotient_bellatrix =
        extract_u64(&bellatrix_map, "MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX")?;
    let proportional_slashing_multiplier_bellatrix =
        extract_u64(&bellatrix_map, "PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX")?;
    let max_bytes_per_transaction = extract_u64(&bellatrix_map, "MAX_BYTES_PER_TRANSACTION")?;
    let max_transactions_per_payload = extract_u64(&bellatrix_map, "MAX_TRANSACTIONS_PER_PAYLOAD")?;
    let bytes_per_logs_bloom = extract_u64(&bellatrix_map, "BYTES_PER_LOGS_BLOOM")?;
    let max_extra_data_bytes = extract_u64(&bellatrix_map, "MAX_EXTRA_DATA_BYTES")?;

    // Uniform across presets (spec constants, not in YAML):
    // SYNC_COMMITTEE_SUBNET_COUNT = 4 per specs/altair/validator.md:80
    let sync_committee_subnet_count: u64 = 4;
    // TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE = 16 per specs/altair/validator.md:79
    let target_aggregators_per_sync_subcommittee: u64 = 16;

    // Derived:
    let sync_subcommittee_size = sync_committee_size / sync_committee_subnet_count;
    let seconds_per_slot = slot_duration_ms / 1000;

    Ok(RuntimeConfig {
        sync_committee_size,
        sync_committee_subnet_count,
        sync_subcommittee_size,
        min_sync_committee_participants,
        epochs_per_sync_committee_period,
        target_aggregators_per_sync_subcommittee,
        update_timeout,
        inactivity_penalty_quotient_altair,
        min_slashing_penalty_quotient_altair,
        proportional_slashing_multiplier_altair,
        inactivity_score_bias,
        inactivity_score_recovery_rate,
        seconds_per_slot,
        genesis_fork_version,
        altair_fork_version,
        altair_fork_epoch,
        genesis_validators_root: [0u8; 32],
        bellatrix_fork_version,
        bellatrix_fork_epoch,
        capella_fork_version,
        capella_fork_epoch,
        terminal_total_difficulty,
        terminal_block_hash,
        terminal_block_hash_activation_epoch,
        inactivity_penalty_quotient_bellatrix,
        min_slashing_penalty_quotient_bellatrix,
        proportional_slashing_multiplier_bellatrix,
        max_bytes_per_transaction,
        max_transactions_per_payload,
        bytes_per_logs_bloom,
        max_extra_data_bytes,
        deposit_contract_address,
        deposit_chain_id,
        slots_per_epoch,
    })
}

// ── Flat YAML parser ──────────────────────────────────────────────────────────

/// Parse a flat (non-nested) YAML file into a `HashMap<String, String>`.
///
/// Only handles the `KEY: value` form. Comments (`#`), blank lines, and
/// YAML anchors are ignored. This is sufficient for the consensus-specs
/// config/preset files, which are all flat key-value structures.
///
/// This avoids `serde_yaml_ng`'s inability to represent integers larger than
/// `u64` (e.g. `TERMINAL_TOTAL_DIFFICULTY: 58750000000000000000000`).
fn parse_flat_yaml(src: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for raw_line in src.lines() {
        // Reject indented lines and list items: this parser handles only flat
        // top-level `KEY: value` pairs. Indented entries (e.g. mainnet's
        // BLOB_SCHEDULE list items) must not be flattened into the map or they
        // would shadow top-level keys of the same name.
        match raw_line.chars().next() {
            Some(' ') | Some('\t') | Some('-') => continue,
            _ => {}
        }
        // Strip trailing comments and whitespace.
        let line = match raw_line.find('#') {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Split on the first colon.
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            // Skip key-only lines (the value is a nested block opener, e.g.
            // `BLOB_SCHEDULE:` followed by indented list items).
            if !key.is_empty() && !value.is_empty() {
                map.insert(key, value);
            }
        }
    }
    map
}

// ── Field extraction helpers ──────────────────────────────────────────────────

/// Parse a `Uint256` from a decimal or `0x`-prefixed hex string in the map.
///
/// Used for `TERMINAL_TOTAL_DIFFICULTY` which may exceed `u64::MAX`.
fn extract_uint256(
    map: &HashMap<String, String>,
    field: &'static str,
) -> Result<Uint256, ConfigError> {
    let raw = map
        .get(field)
        .ok_or(ConfigError::MissingField(field))?
        .trim();
    Uint256::from_str(raw).map_err(|_| ConfigError::InvalidValue {
        field,
        value: raw.to_string(),
    })
}

/// Parse a `Hash256` from a `0x`-prefixed 32-byte hex string in the map.
///
/// Used for `TERMINAL_BLOCK_HASH`.
fn extract_hash256(
    map: &HashMap<String, String>,
    field: &'static str,
) -> Result<Hash256, ConfigError> {
    let raw = map
        .get(field)
        .ok_or(ConfigError::MissingField(field))?
        .trim();
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or_else(|| ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        })?;
    if hex.len() != 64 {
        return Err(ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        });
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| {
            ConfigError::InvalidValue {
                field,
                value: raw.to_string(),
            }
        })?;
    }
    Ok(Hash256::from_array(bytes))
}

fn extract_u64(map: &HashMap<String, String>, field: &'static str) -> Result<u64, ConfigError> {
    let raw = map
        .get(field)
        .ok_or(ConfigError::MissingField(field))?
        .trim();
    // Support hex (`0x...`) and decimal.
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        })
    } else {
        raw.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        })
    }
}

/// Parse a 20-byte Ethereum execution address from a `0x`-prefixed 40-hex-char string.
///
/// Used for `DEPOSIT_CONTRACT_ADDRESS` (e.g. `0x00000000219ab540356cBB839Cbe05303d7705Fa`).
fn extract_address20(
    map: &HashMap<String, String>,
    field: &'static str,
) -> Result<[u8; 20], ConfigError> {
    let raw = map
        .get(field)
        .ok_or(ConfigError::MissingField(field))?
        .trim();
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or_else(|| ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        })?;
    if hex.len() != 40 {
        return Err(ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        });
    }
    let mut bytes = [0u8; 20];
    for i in 0..20 {
        bytes[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| {
            ConfigError::InvalidValue {
                field,
                value: raw.to_string(),
            }
        })?;
    }
    Ok(bytes)
}

/// Parse a 4-byte fork version from a hex string like `0x00000000` or decimal `0`.
///
/// The consensus-specs YAML encodes fork versions as `0xAABBCCDD` (hex).
fn extract_version(
    map: &HashMap<String, String>,
    field: &'static str,
) -> Result<[u8; 4], ConfigError> {
    let raw = map
        .get(field)
        .ok_or(ConfigError::MissingField(field))?
        .trim();
    let n: u32 = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|_| ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        })?
    } else {
        raw.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
            field,
            value: raw.to_string(),
        })?
    };
    Ok(n.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Path prefix to the consensus-specs mainnet config (without `.yaml`).
    fn mainnet_config_prefix() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        PathBuf::from(home)
            .join("dev")
            .join("consensus-specs")
            .join("configs")
            .join("mainnet")
    }

    /// Returns `true` if the consensus-specs mainnet config YAML is present.
    fn mainnet_config_available() -> bool {
        mainnet_config_prefix().with_extension("yaml").exists()
    }

    #[test]
    fn mainnet_altair_fork_epoch() {
        if !mainnet_config_available() {
            eprintln!("consensus-specs not found — skipping mainnet YAML loader test");
            return;
        }
        let cfg =
            load_config_dir(&mainnet_config_prefix()).expect("load_config_dir should succeed");
        // Per ~/dev/consensus-specs/configs/mainnet.yaml: ALTAIR_FORK_EPOCH: 74240
        assert_eq!(cfg.altair_fork_epoch, 74_240);
    }

    #[test]
    fn mainnet_seconds_per_slot() {
        if !mainnet_config_available() {
            eprintln!("consensus-specs not found — skipping mainnet YAML loader test");
            return;
        }
        let cfg =
            load_config_dir(&mainnet_config_prefix()).expect("load_config_dir should succeed");
        // Per mainnet.yaml: SLOT_DURATION_MS: 12000 → seconds_per_slot = 12
        assert_eq!(cfg.seconds_per_slot * 1000, 12_000);
    }

    #[test]
    fn mainnet_genesis_fork_version() {
        if !mainnet_config_available() {
            eprintln!("consensus-specs not found — skipping mainnet YAML loader test");
            return;
        }
        let cfg =
            load_config_dir(&mainnet_config_prefix()).expect("load_config_dir should succeed");
        // Per mainnet.yaml: GENESIS_FORK_VERSION: 0x00000000
        assert_eq!(cfg.genesis_fork_version, [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn mainnet_altair_fork_version() {
        if !mainnet_config_available() {
            eprintln!("consensus-specs not found — skipping mainnet YAML loader test");
            return;
        }
        let cfg =
            load_config_dir(&mainnet_config_prefix()).expect("load_config_dir should succeed");
        // Per mainnet.yaml: ALTAIR_FORK_VERSION: 0x01000000
        assert_eq!(cfg.altair_fork_version, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn mainnet_assert_matches_preset() {
        if !mainnet_config_available() {
            eprintln!("consensus-specs not found — skipping mainnet YAML loader test");
            return;
        }
        use crate::eth_spec::MainnetEthSpec;
        let cfg =
            load_config_dir(&mainnet_config_prefix()).expect("load_config_dir should succeed");
        // Mainnet YAML should match MainnetEthSpec compile-time consts.
        cfg.assert_matches_preset::<MainnetEthSpec>()
            .expect("mainnet YAML should match MainnetEthSpec");
    }

    #[test]
    fn parse_flat_yaml_handles_large_integers() {
        // Ensure the flat parser doesn't fail on TERMINAL_TOTAL_DIFFICULTY.
        let src = "TERMINAL_TOTAL_DIFFICULTY: 58750000000000000000000\nFOO: 123\n";
        let map = parse_flat_yaml(src);
        assert_eq!(
            map.get("TERMINAL_TOTAL_DIFFICULTY").map(String::as_str),
            Some("58750000000000000000000")
        );
        assert_eq!(map.get("FOO").map(String::as_str), Some("123"));
    }

    #[test]
    fn parse_flat_yaml_hex_version() {
        let src = "GENESIS_FORK_VERSION: 0x00000000\nALTAIR_FORK_VERSION: 0x01000000\n";
        let map = parse_flat_yaml(src);
        let gfv = extract_version(&map, "GENESIS_FORK_VERSION").unwrap();
        assert_eq!(gfv, [0x00, 0x00, 0x00, 0x00]);
        let afv = extract_version(&map, "ALTAIR_FORK_VERSION").unwrap();
        assert_eq!(afv, [0x01, 0x00, 0x00, 0x00]);
    }
}
