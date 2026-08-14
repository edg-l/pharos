//! SSZ `Encode`, `Decode`, and `TreeHash` impls for `pharos_utils` consensus
//! newtypes (`Slot`, `Epoch`, `Gwei`, `ValidatorIndex`, `CommitteeIndex`).
//!
//! All five types are transparent wrappers over `u64` and are treated as
//! `uint64` by SSZ (8 bytes, little-endian) and as `Basic` by `TreeHash`.
//!
//! The spec defines these in `specs/phase0/beacon-chain.md:165-169`:
//! - `Slot` — uint64
//! - `Epoch` — uint64
//! - `CommitteeIndex` — uint64
//! - `ValidatorIndex` — uint64
//! - `Gwei` — uint64

use crate::{
    decode::Decode,
    encode::Encode,
    error::SszError,
    tree_hash::{TreeHash, TreeHashType},
};
use pharos_utils::{CommitteeIndex, Epoch, Gwei, Hash256, Slot, ValidatorIndex};

macro_rules! impl_ssz_newtype_u64 {
    ($t:ty) => {
        impl Encode for $t {
            const IS_FIXED_SIZE: bool = true;

            fn ssz_fixed_len() -> usize {
                8
            }

            fn ssz_bytes_len(&self) -> usize {
                8
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self.0.to_le_bytes());
            }
        }

        impl Decode for $t {
            const IS_FIXED_SIZE: bool = true;

            fn ssz_fixed_len() -> usize {
                8
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
                if bytes.len() != 8 {
                    return Err(SszError::InvalidByteLength {
                        found: bytes.len(),
                        expected: 8,
                    });
                }
                let arr: [u8; 8] = bytes.try_into().expect("length checked above");
                Ok(Self(u64::from_le_bytes(arr)))
            }
        }

        impl TreeHash for $t {
            const TREE_HASH_TYPE: TreeHashType = TreeHashType::Basic;

            fn tree_hash_root(&self) -> Hash256 {
                let mut chunk = [0u8; 32];
                chunk[..8].copy_from_slice(&self.0.to_le_bytes());
                Hash256::from_array(chunk)
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                self.0.to_le_bytes().to_vec()
            }
        }
    };
}

impl_ssz_newtype_u64!(Slot);
impl_ssz_newtype_u64!(Epoch);
impl_ssz_newtype_u64!(Gwei);
impl_ssz_newtype_u64!(ValidatorIndex);
impl_ssz_newtype_u64!(CommitteeIndex);
