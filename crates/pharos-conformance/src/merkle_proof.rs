//! Conformance runner for `deneb/merkle_proof/single_merkle_proof` fixtures.
//!
//! Fixture path:
//!   `<root>/<preset>/deneb/merkle_proof/single_merkle_proof/<ObjectType>/<case>/`
//!
//! Each case contains:
//!   - `object.ssz_snappy` — SSZ-encoded container (e.g. `BeaconBlockBody`)
//!   - `proof.yaml`        — `leaf`, `leaf_index`, `branch` fields
//!
//! Test logic:
//!   1. Decode the container from `object.ssz_snappy`.
//!   2. Compute `root = tree_hash_root(object)`.
//!   3. Read `leaf`, `leaf_index`, and `branch` from `proof.yaml`.
//!   4. Derive `depth = KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` (17).
//!   5. Derive `index = leaf_index - 2^depth` (positional).
//!   6. Call `is_valid_merkle_branch(leaf, branch, depth, index, root)` and assert true.
//!
//! Only the `BeaconBlockBody` object type is tested (the only type the spec
//! currently provides fixtures for under this handler).

use std::path::Path;

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_types::deneb::{
    KZG_COMMITMENT_INCLUSION_PROOF_DEPTH, MainnetBeaconBlockBody, MinimalBeaconBlockBody,
};
use pharos_utils::Hash256;

use crate::error::ConformanceError;
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::snappy::decompress_raw;

/// Result of running all merkle_proof conformance tests for one preset.
pub struct MerkleProofResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

/// Run all `deneb/merkle_proof` tests for `mainnet` preset.
pub fn run_merkle_proof_mainnet(root: &Path) -> MerkleProofResult {
    run_merkle_proof_preset(&root.join("mainnet"), "mainnet")
}

/// Run all `deneb/merkle_proof` tests for `minimal` preset.
pub fn run_merkle_proof_minimal(root: &Path) -> MerkleProofResult {
    run_merkle_proof_preset(&root.join("minimal"), "minimal")
}

fn run_merkle_proof_preset(preset_dir: &Path, preset_name: &str) -> MerkleProofResult {
    let base = preset_dir.join("deneb/merkle_proof/single_merkle_proof");
    if !base.is_dir() {
        return MerkleProofResult {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: vec![],
        };
    }

    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut skip = 0u64;
    let mut failures = Vec::new();

    let object_type_dirs = read_dir_sorted(&base).unwrap_or_default();
    for object_type_dir in object_type_dirs {
        if !object_type_dir.is_dir() {
            continue;
        }
        let object_type = dir_name(&object_type_dir);
        let case_dirs = read_dir_sorted(&object_type_dir).unwrap_or_default();
        for case_dir in case_dirs {
            if !case_dir.is_dir() {
                continue;
            }
            let case_name = format!(
                "{preset_name}/deneb/merkle_proof/single_merkle_proof/{object_type}/{}",
                dir_name(&case_dir)
            );
            match run_one_case(preset_name, &object_type, &case_dir, &case_name) {
                Ok(true) => pass += 1,
                Ok(false) => skip += 1,
                Err(e) => {
                    fail += 1;
                    failures.push(format!("`{case_name}`: {e}"));
                }
            }
        }
    }

    MerkleProofResult {
        pass,
        fail,
        skip,
        failures,
    }
}

fn run_one_case(
    preset: &str,
    object_type: &str,
    case_dir: &Path,
    case_label: &str,
) -> Result<bool, ConformanceError> {
    let object_path = case_dir.join("object.ssz_snappy");
    let proof_path = case_dir.join("proof.yaml");
    if !object_path.exists() || !proof_path.exists() {
        return Ok(false);
    }

    let compressed = std::fs::read(&object_path)?;
    let ssz_bytes = decompress_raw(&compressed)?;

    let proof_text = std::fs::read_to_string(&proof_path)?;
    let proof_val: serde_yaml_ng::Value = serde_yaml_ng::from_str(&proof_text)
        .map_err(|e| ConformanceError::MalformedFixture(format!("proof.yaml parse error: {e}")))?;

    let leaf_hex = proof_val["leaf"]
        .as_str()
        .ok_or_else(|| ConformanceError::MalformedFixture("missing 'leaf'".into()))?;
    let leaf_index: u64 = proof_val["leaf_index"]
        .as_u64()
        .ok_or_else(|| ConformanceError::MalformedFixture("missing 'leaf_index'".into()))?;
    let branch_seq = proof_val["branch"]
        .as_sequence()
        .ok_or_else(|| ConformanceError::MalformedFixture("missing 'branch'".into()))?;

    let leaf = parse_hash256(leaf_hex, "leaf")?;
    let branch: Vec<Hash256> = branch_seq
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| {
                    ConformanceError::MalformedFixture("branch entry not a string".into())
                })
                .and_then(|s| parse_hash256(s, "branch entry"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let depth = KZG_COMMITMENT_INCLUSION_PROOF_DEPTH as u64;
    let positional_index = leaf_index.checked_sub(1u64 << depth).ok_or_else(|| {
        ConformanceError::MalformedFixture(format!("leaf_index {leaf_index} < 2^depth {depth}"))
    })?;

    // Compute the root by decoding the object and calling tree_hash_root.
    let root = match (preset, object_type) {
        ("mainnet", "BeaconBlockBody") => {
            let body = MainnetBeaconBlockBody::from_ssz_bytes(&ssz_bytes)?;
            // Verify round-trip.
            let re_encoded = body.as_ssz_bytes();
            if re_encoded != ssz_bytes {
                return Err(ConformanceError::EncodeRoundTrip {
                    case: case_label.into(),
                    got_hex: hex::encode(&re_encoded),
                    want_hex: hex::encode(&ssz_bytes),
                });
            }
            body.tree_hash_root()
        }
        ("minimal", "BeaconBlockBody") => {
            let body = MinimalBeaconBlockBody::from_ssz_bytes(&ssz_bytes)?;
            let re_encoded = body.as_ssz_bytes();
            if re_encoded != ssz_bytes {
                return Err(ConformanceError::EncodeRoundTrip {
                    case: case_label.into(),
                    got_hex: hex::encode(&re_encoded),
                    want_hex: hex::encode(&ssz_bytes),
                });
            }
            body.tree_hash_root()
        }
        _ => {
            eprintln!(
                "skipping merkle_proof/{object_type} for preset {preset}: not in dispatch table"
            );
            return Ok(false);
        }
    };

    use pharos_stf::phase0::operations::deposit::is_valid_merkle_branch;
    let valid = is_valid_merkle_branch(&leaf, &branch, depth, positional_index, &root);
    if valid {
        Ok(true)
    } else {
        Err(ConformanceError::MalformedFixture(format!(
            "is_valid_merkle_branch returned false: \
             leaf_index={leaf_index} depth={depth} idx={positional_index} \
             leaf=0x{} root=0x{}",
            hex::encode(leaf.as_ref()),
            hex::encode(root.as_ref()),
        )))
    }
}

fn parse_hash256(s: &str, field: &str) -> Result<Hash256, ConformanceError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| {
        ConformanceError::MalformedFixture(format!("{field}: hex decode error: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(ConformanceError::MalformedFixture(format!(
            "{field}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash256::from_array(arr))
}
