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
