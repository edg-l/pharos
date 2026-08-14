//! SSZ `Union` codec stub.
//!
//! Phase 0 containers contain no `Union` variants. No `ssz_generic` test
//! handler exercises classical unions (only `compatible_unions`, which is an
//! EIP-7916 extension that we explicitly skip).
//!
//! This trait slot is reserved so that future forks can fill it in without an
//! API break. The `unimplemented!()` bodies ensure that any accidental call
//! fails loudly rather than silently.

/// Stub trait for SSZ `Union` types.
///
/// Full codec is deferred to the milestone when the first fork requires it.
/// All methods call `unimplemented!()`.
pub trait SszUnion: Sized {
    /// Encode this union value into `buf`.
    fn ssz_union_append(&self, _buf: &mut Vec<u8>) {
        unimplemented!("SszUnion codec not implemented in M0")
    }

    /// Decode a union value from `bytes`.
    fn ssz_union_from_bytes(_bytes: &[u8]) -> Result<Self, crate::error::SszError> {
        unimplemented!("SszUnion codec not implemented in M0")
    }

    /// Compute the `hash_tree_root` of this union value.
    fn ssz_union_tree_hash_root(&self) -> pharos_utils::Hash256 {
        unimplemented!("SszUnion codec not implemented in M0")
    }
}
