//! RocksDB key encoding helpers.
//!
//! Slot keys are stored as **big-endian `u64`** so that RocksDB's default
//! lexicographic comparator produces the same order as numeric order for
//! unsigned integers. This enables correct `Iterator::seek`-based range scans
//! on the `slot_to_block_root` column family.
//!
//! Per `D-rocksdb`: "Use big-endian for slot keys so `Iterator::seek` does
//! range scans correctly."

use pharos_types::phase0::primitives::{Root, Slot};

use crate::error::StorageError;

// ── Blob sidecar key layout (D-blob-store-cf-keyed-by-root-index) ─────────────
//
// key = block_root (32 bytes) || index (8 bytes, big-endian u64)
//
// The big-endian index suffix means that RocksDB's lexicographic comparator
// produces the same order as numeric index order within the same block-root
// prefix (0 < 1 < 2 …). A prefix iterator on the 32-byte `block_root` thus
// yields all sidecars in ascending index order without a separate sort step.

/// Encodes a `Slot` as an 8-byte big-endian key.
///
/// Big-endian order is required for correct lexicographic range scans on the
/// `slot_to_block_root` CF.
pub fn slot_key(slot: Slot) -> [u8; 8] {
    slot.0.to_be_bytes()
}

/// Returns the raw byte slice for a `Root` key.
///
/// `Root` is a 32-byte `FixedBytes<32>`; its byte representation is already
/// canonical for content-addressed keys in `blocks`, `block_root_to_slot`,
/// and `states` CFs.
pub fn root_key(root: &Root) -> &[u8] {
    root.as_slice()
}

/// Encodes a `(block_root, blob_index)` pair as the 40-byte compound key used
/// in the `blob-sidecars` CF.
///
/// Layout: `block_root[0..32] || index.to_be_bytes()[0..8]`.
/// Big-endian index ensures lexicographic order == numeric index order within
/// the same `block_root` prefix, enabling a single prefix scan to return
/// all sidecars in ascending index order.
///
/// Per `D-blob-store-cf-keyed-by-root-index`.
pub fn blob_sidecar_key(root: &Root, index: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(root.as_slice());
    key[32..40].copy_from_slice(&index.to_be_bytes());
    key
}

/// Encodes a `(slot, proposer_index, header_root)` triple as the 48-byte
/// compound key used in the `slasher-proposers` CF (Phase B slasher).
///
/// Layout: `slot.to_be_bytes()[0..8] || proposer_index.to_be_bytes()[0..8] ||
/// header_root[0..32]`.
///
/// The 16-byte `slot || proposer_index` prefix groups every distinct header a
/// proposer signed at a slot; the 32-byte `header_root` suffix keeps two
/// distinct blocks (a double-block) under separate keys so both survive and the
/// prefix scan finds the slashable pair.
///
/// Per `D-slasher-proposer-index-cf`.
pub fn slasher_proposer_key(slot: Slot, proposer_index: u64, header_root: &Root) -> [u8; 48] {
    let mut key = [0u8; 48];
    key[..8].copy_from_slice(&slot.0.to_be_bytes());
    key[8..16].copy_from_slice(&proposer_index.to_be_bytes());
    key[16..48].copy_from_slice(header_root.as_slice());
    key
}

/// Returns the 16-byte `slot || proposer_index` prefix used to prefix-scan the
/// `slasher-proposers` CF for every header a proposer signed at a slot.
///
/// Per `D-slasher-proposer-index-cf`.
pub fn slasher_proposer_prefix(slot: Slot, proposer_index: u64) -> [u8; 16] {
    let mut prefix = [0u8; 16];
    prefix[..8].copy_from_slice(&slot.0.to_be_bytes());
    prefix[8..16].copy_from_slice(&proposer_index.to_be_bytes());
    prefix
}

/// Parses a big-endian 8-byte slice back into a `Slot`.
///
/// Returns `StorageError::InvalidKeyLength` if `bytes.len() != 8`.
pub fn parse_slot_key(bytes: &[u8]) -> Result<Slot, StorageError> {
    if bytes.len() != 8 {
        return Err(StorageError::InvalidKeyLength {
            got: bytes.len(),
            expected: 8,
        });
    }
    let arr: [u8; 8] = bytes.try_into().expect("length already checked");
    Ok(Slot(u64::from_be_bytes(arr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_key_roundtrip() {
        let slot = Slot(12345);
        let encoded = slot_key(slot);
        let decoded = parse_slot_key(&encoded).expect("roundtrip must succeed");
        assert_eq!(decoded, slot);
    }

    #[test]
    fn parse_slot_key_invalid_length() {
        let result = parse_slot_key(&[1, 2, 3]);
        match result {
            Err(StorageError::InvalidKeyLength { got, expected }) => {
                assert_eq!(got, 3);
                assert_eq!(expected, 8);
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }
}
