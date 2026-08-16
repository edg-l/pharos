//! Conformance runner for `deneb/merkle_proof/single_merkle_proof` and
//! `electra/merkle_proof/single_merkle_proof` fixtures.
//!
//! Fixture path:
//!   `<root>/<preset>/{deneb,electra}/merkle_proof/single_merkle_proof/<ObjectType>/<case>/`
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
//! Both deneb and electra use `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH = 17`.

use std::path::Path;

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_types::deneb::{
    KZG_COMMITMENT_INCLUSION_PROOF_DEPTH, MainnetBeaconBlockBody as DenebMainnetBody,
    MinimalBeaconBlockBody as DenebMinimalBody,
};
use pharos_types::electra::{
    MainnetBeaconBlockBody as ElectraMainnetBody, MinimalBeaconBlockBody as ElectraMinimalBody,
};
use pharos_utils::Hash256;

use crate::error::ConformanceError;
use crate::fs_util::{dir_name, read_dir_sorted};
use crate::snappy::decompress_raw;
use crate::task::{CaseFn, CaseOutcome, CaseTask};

/// Result of running all merkle_proof conformance tests for one preset.
pub struct MerkleProofResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
}

/// Run all `deneb/merkle_proof` tests for `mainnet` preset.
pub fn run_merkle_proof_mainnet(root: &Path) -> MerkleProofResult {
    run_merkle_proof_preset("deneb", &root.join("mainnet"), "mainnet")
}

/// Run all `deneb/merkle_proof` tests for `minimal` preset.
pub fn run_merkle_proof_minimal(root: &Path) -> MerkleProofResult {
    run_merkle_proof_preset("deneb", &root.join("minimal"), "minimal")
}

/// Run all `electra/merkle_proof` tests for `mainnet` preset.
pub fn run_merkle_proof_electra_mainnet(root: &Path) -> MerkleProofResult {
    run_merkle_proof_preset("electra", &root.join("mainnet"), "mainnet")
}

/// Run all `electra/merkle_proof` tests for `minimal` preset.
pub fn run_merkle_proof_electra_minimal(root: &Path) -> MerkleProofResult {
    run_merkle_proof_preset("electra", &root.join("minimal"), "minimal")
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per merkle_proof test case in the same walk-order as
/// `run_merkle_proof_preset`. Called by the Phase 7 flat work-pool.
///
/// `fork` must be `"deneb"` or `"electra"`.
pub fn enumerate_merkle_proof(
    root: &Path,
    fork: &'static str,
    preset: &'static str,
    row_ordinal: u32,
) -> Vec<CaseTask> {
    let preset_dir = root.join(preset);
    let base = preset_dir
        .join(fork)
        .join("merkle_proof/single_merkle_proof");
    if !base.is_dir() {
        return Vec::new();
    }

    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    let object_type_dirs = read_dir_sorted(&base).unwrap_or_default();
    for object_type_dir in object_type_dirs {
        if !object_type_dir.is_dir() {
            continue;
        }
        let object_type: String = dir_name(&object_type_dir);
        let case_dirs = read_dir_sorted(&object_type_dir).unwrap_or_default();
        for case_dir in case_dirs {
            if !case_dir.is_dir() {
                continue;
            }
            let case_ordinal = ordinal;
            ordinal += 1;
            let case_name = format!(
                "{preset}/{fork}/merkle_proof/single_merkle_proof/{}/{}",
                object_type,
                dir_name(&case_dir)
            );
            let preset_owned: String = preset.to_string();
            let fork_owned: String = fork.to_string();
            let object_type_owned: String = object_type.clone();
            let run: CaseFn = Box::new(move || {
                match run_one_case(
                    &fork_owned,
                    &preset_owned,
                    &object_type_owned,
                    &case_dir,
                    &case_name,
                ) {
                    Ok(true) => CaseOutcome::Pass,
                    Ok(false) => CaseOutcome::Skip,
                    Err(e) => CaseOutcome::Fail(format!("`{case_name}`: {e}")),
                }
            });
            tasks.push(CaseTask {
                row_ordinal,
                case_ordinal,
                run,
            });
        }
    }

    tasks
}

fn run_merkle_proof_preset(fork: &str, preset_dir: &Path, preset_name: &str) -> MerkleProofResult {
    let base = preset_dir
        .join(fork)
        .join("merkle_proof/single_merkle_proof");
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
                "{preset_name}/{fork}/merkle_proof/single_merkle_proof/{object_type}/{}",
                dir_name(&case_dir)
            );
            match run_one_case(fork, preset_name, &object_type, &case_dir, &case_name) {
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
    fork: &str,
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
    let root = match (fork, preset, object_type) {
        ("deneb", "mainnet", "BeaconBlockBody") => {
            let body = DenebMainnetBody::from_ssz_bytes(&ssz_bytes)?;
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
        ("deneb", "minimal", "BeaconBlockBody") => {
            let body = DenebMinimalBody::from_ssz_bytes(&ssz_bytes)?;
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
        ("electra", "mainnet", "BeaconBlockBody") => {
            let body = ElectraMainnetBody::from_ssz_bytes(&ssz_bytes)?;
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
        ("electra", "minimal", "BeaconBlockBody") => {
            let body = ElectraMinimalBody::from_ssz_bytes(&ssz_bytes)?;
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
                "skipping {fork}/merkle_proof/{object_type} for preset {preset}: not in dispatch table"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::fixtures_root;
    use crate::task::CaseOutcome;

    fn drain_tasks(tasks: Vec<CaseTask>) -> (u64, u64, u64) {
        let mut pass = 0u64;
        let mut fail = 0u64;
        let mut skip = 0u64;
        for task in tasks {
            match (task.run)() {
                CaseOutcome::Pass => pass += 1,
                CaseOutcome::Fail(_) => fail += 1,
                CaseOutcome::Skip => skip += 1,
            }
        }
        (pass, fail, skip)
    }

    #[test]
    fn enumerate_merkle_proof_parity_mainnet() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_merkle_proof_mainnet(&root);
        let (ep, ef, es) = drain_tasks(enumerate_merkle_proof(&root, "deneb", "mainnet", 85));
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_merkle_proof deneb mainnet counts differ"
        );
    }

    #[test]
    fn enumerate_merkle_proof_parity_minimal() {
        let Some(root) = fixtures_root() else {
            return; // skip cleanly when fixtures absent
        };
        let run_result = run_merkle_proof_minimal(&root);
        let (ep, ef, es) = drain_tasks(enumerate_merkle_proof(&root, "deneb", "minimal", 86));
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_merkle_proof deneb minimal counts differ"
        );
    }

    #[test]
    fn enumerate_merkle_proof_electra_parity_mainnet() {
        let Some(root) = fixtures_root() else {
            return;
        };
        let run_result = run_merkle_proof_electra_mainnet(&root);
        let (ep, ef, es) = drain_tasks(enumerate_merkle_proof(&root, "electra", "mainnet", 85));
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_merkle_proof electra mainnet counts differ"
        );
    }

    #[test]
    fn enumerate_merkle_proof_electra_parity_minimal() {
        let Some(root) = fixtures_root() else {
            return;
        };
        let run_result = run_merkle_proof_electra_minimal(&root);
        let (ep, ef, es) = drain_tasks(enumerate_merkle_proof(&root, "electra", "minimal", 86));
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_merkle_proof electra minimal counts differ"
        );
    }
}
