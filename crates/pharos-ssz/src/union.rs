//! SSZ `Union` and `CompatibleUnion` codec.
//!
//! ## Legacy `Union`
//!
//! Phase 0 containers contain no `Union` variants. The `SszUnion` trait slot
//! is retained so that future forks can fill it in without an API break.
//!
//! ## `CompatibleUnion` (EIP-7495)
//!
//! `CompatibleUnion({selector: type})` is a tagged union whose type options are
//! identified by a `u8` selector in the range `1..=127`.
//!
//! ### Wire format
//!
//! `selector_byte || serialize(data)` — same as the classical `Union` encoding
//! but limited to selectors `1..=127`.
//!
//! ### Merkleization
//!
//! `mix_in_selector(hash_tree_root(value.data), value.selector)`
//!
//! ### Legality rules
//!
//! - Selector 0 is illegal (reserved / not-present).
//! - Selectors above 127 are illegal.
//! - An empty input (`len < 1`) is illegal.
//! - The data portion must round-trip through the selected type's codec.

use crate::{
    Decode, Encode,
    error::SszError,
    tree_hash::{TreeHash, TreeHashType, mix_in_selector},
};
use pharos_utils::Hash256;

// ── SszUnion stub ─────────────────────────────────────────────────────────────

/// Stub trait for SSZ `Union` types.
///
/// Full codec is reserved for the milestone when the first fork requires a
/// classical union. All methods call `unimplemented!()`.
pub trait SszUnion: Sized {
    /// Encode this union value into `buf`.
    fn ssz_union_append(&self, _buf: &mut Vec<u8>) {
        unimplemented!("SszUnion codec not implemented")
    }

    /// Decode a union value from `bytes`.
    fn ssz_union_from_bytes(_bytes: &[u8]) -> Result<Self, SszError> {
        unimplemented!("SszUnion codec not implemented")
    }

    /// Compute the `hash_tree_root` of this union value.
    fn ssz_union_tree_hash_root(&self) -> Hash256 {
        unimplemented!("SszUnion codec not implemented")
    }
}

// ── CompatibleUnion trait ─────────────────────────────────────────────────────

/// Trait for EIP-7495 compatible union values.
///
/// A type implementing `CompatibleUnionValue` provides:
/// - Decoding from `(selector, data_bytes)`.
/// - Re-encoding back to `data_bytes` for the round-trip check.
/// - `tree_hash_root` of the data value.
pub trait CompatibleUnionValue: Sized + Clone + PartialEq + Eq {
    /// Decode from a `(selector, data_bytes)` pair. Returns `Err` if the
    /// selector is not recognized or the data is invalid.
    fn from_selector_and_bytes(selector: u8, data: &[u8]) -> Result<Self, SszError>;

    /// Re-encode the data field (not including the selector byte) into `buf`.
    fn data_ssz_append(&self, buf: &mut Vec<u8>);

    /// Hash-tree-root of the data field.
    fn data_tree_hash_root(&self) -> Hash256;

    /// The selector of this value.
    fn selector(&self) -> u8;
}

// ── CompatibleUnion<V> runtime wrapper ───────────────────────────────────────

/// Runtime wrapper around a `CompatibleUnionValue` implementing SSZ
/// `Encode + Decode + TreeHash`.
///
/// `T` must implement `CompatibleUnionValue`. The wrapper handles the
/// selector-byte prefix and the `mix_in_selector` Merkleization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompatibleUnion<V: CompatibleUnionValue> {
    inner: V,
}

impl<V: CompatibleUnionValue> CompatibleUnion<V> {
    /// Construct from a value.
    pub fn new(inner: V) -> Self {
        Self { inner }
    }

    /// Access the inner value.
    pub fn inner(&self) -> &V {
        &self.inner
    }

    /// The selector byte for this union value.
    pub fn selector(&self) -> u8 {
        self.inner.selector()
    }
}

impl<V: CompatibleUnionValue> Encode for CompatibleUnion<V> {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        crate::encode::BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        let mut buf = Vec::new();
        self.inner.data_ssz_append(&mut buf);
        1 + buf.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.push(self.inner.selector());
        self.inner.data_ssz_append(buf);
    }
}

impl<V: CompatibleUnionValue> Decode for CompatibleUnion<V> {
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        crate::encode::BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        if bytes.is_empty() {
            return Err(SszError::Custom("CompatibleUnion: empty input".into()));
        }
        let selector = bytes[0];
        // Selectors 0 and 128..=255 are illegal.
        if selector == 0 || selector > 127 {
            return Err(SszError::Custom(format!(
                "CompatibleUnion: illegal selector {selector}"
            )));
        }
        let data = &bytes[1..];
        let inner = V::from_selector_and_bytes(selector, data)?;
        Ok(Self { inner })
    }
}

impl<V: CompatibleUnionValue> TreeHash for CompatibleUnion<V> {
    // A union is a composite type, so it advertises `Container` (the only
    // composite `TreeHashType`), which is correct for packing decisions in a
    // parent container — a union is never packed inline. The root itself is NOT
    // computed by container merkleization; per EIP-7495 it is
    // `mix_in_selector(hash_tree_root(data), selector)` (see `tree_hash_root`).
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        let data_root = self.inner.data_tree_hash_root();
        mix_in_selector(data_root, self.inner.selector())
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("CompatibleUnion is not a basic type and is never packed")
    }
}
