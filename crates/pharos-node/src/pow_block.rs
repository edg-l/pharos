//! Production `PowBlockProvider` implementation for the Pharos beacon node.
//!
//! `EnginePowBlockProvider` wraps an `EngineHandle` and satisfies the
//! `PowBlockProvider` trait required by `pharos_fork_choice::on_block`'s
//! merge-transition guard. It calls `eth_getBlockByHash` on the EL to retrieve
//! PoW-chain block data.
//!
//! Per `D-engine-head-driver`.

use pharos_engine::EngineHandle;
use pharos_fork_choice::{PowBlock, PowBlockError, PowBlockProvider};
use pharos_utils::{Hash256, Uint256};

// ── EnginePowBlockProvider ────────────────────────────────────────────────────

/// `PowBlockProvider` backed by an `EngineHandle` (`eth_getBlockByHash`).
///
/// Called by the block-ingestion loop when passing a `PowBlockProvider` to
/// `pharos_fork_choice::on_block` for Bellatrix merge-transition blocks.
/// For Phase0/Altair fixtures the `NoopPowBlockProvider` is used instead.
pub struct EnginePowBlockProvider {
    engine: EngineHandle,
}

impl EnginePowBlockProvider {
    /// Construct a new provider wrapping the given engine handle.
    pub fn new(engine: EngineHandle) -> Self {
        Self { engine }
    }
}

impl PowBlockProvider for EnginePowBlockProvider {
    fn get_pow_block(&self, hash: Hash256) -> Result<Option<PowBlock>, PowBlockError> {
        // Format the hash as `0x`-prefixed hex for the JSON-RPC call.
        let hash_hex = {
            let bytes = hash.as_slice();
            let mut s = String::with_capacity(2 + bytes.len() * 2);
            s.push_str("0x");
            for b in bytes {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
            }
            s
        };

        let header_opt = self
            .engine
            .get_block_by_hash_blocking(hash_hex)
            .map_err(|e| PowBlockError::ExecutionLayer(e.to_string()))?;

        let Some(header) = header_opt else {
            return Ok(None);
        };

        // Parse `block_hash`.
        let block_hash = parse_hash256(&header.hash)
            .map_err(|e| PowBlockError::ExecutionLayer(format!("invalid block hash: {e}")))?;

        // Parse `parent_hash`.
        let parent_hash = parse_hash256(&header.parent_hash)
            .map_err(|e| PowBlockError::ExecutionLayer(format!("invalid parent hash: {e}")))?;

        // Parse `total_difficulty` — may be `None` for post-merge blocks.
        let total_difficulty = match &header.total_difficulty {
            None => Uint256::ZERO,
            Some(s) => parse_uint256(s).map_err(|e| {
                PowBlockError::ExecutionLayer(format!("invalid totalDifficulty: {e}"))
            })?,
        };

        Ok(Some(PowBlock {
            block_hash,
            parent_hash,
            total_difficulty,
        }))
    }
}

// ── Hex parsing helpers ───────────────────────────────────────────────────────

fn parse_hash256(s: &str) -> Result<Hash256, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?;
    }
    Ok(Hash256::from_array(out))
}

fn parse_uint256(s: &str) -> Result<Uint256, String> {
    s.parse::<Uint256>()
}
