//! Tiny YAML helpers for spec-test metadata files.
//!
//! We use a hand-written micro-parser rather than a derived schema — the SSZ
//! test path only needs the `root` field; no per-container YAML schema needed.

use std::path::Path;

use pharos_utils::Hash256;

use crate::error::ConformanceError;

/// Read `roots.yaml` (or `meta.yaml`) and extract the `root` field as a `Hash256`.
///
/// Expected format:
/// ```yaml
/// root: 0x<hex>
/// ```
pub fn read_root_from_file(path: &Path) -> Result<Hash256, ConformanceError> {
    let text = std::fs::read_to_string(path)?;
    read_root_from_str(&text)
}

/// Parse the `root: 0x<hex>` field from a YAML string.
pub fn read_root_from_str(text: &str) -> Result<Hash256, ConformanceError> {
    let val: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(text).map_err(|e| ConformanceError::Yaml(e.to_string()))?;

    let root_str = val
        .get("root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConformanceError::Yaml("missing 'root' field".into()))?;

    parse_root_hex(root_str)
}

/// Parse a `0x`-prefixed hex string into a `Hash256`.
pub fn parse_root_hex(s: &str) -> Result<Hash256, ConformanceError> {
    let hex_str = s
        .strip_prefix("0x")
        .ok_or_else(|| ConformanceError::Yaml(format!("root has no 0x prefix: {s}")))?;

    let bytes = hex::decode(hex_str)
        .map_err(|e| ConformanceError::Yaml(format!("root hex decode error: {e}")))?;

    if bytes.len() != 32 {
        return Err(ConformanceError::Yaml(format!(
            "root is {} bytes, expected 32",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash256::from(arr))
}
