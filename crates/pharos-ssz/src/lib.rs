//! In-house SSZ encoding, decoding, and Merkleization.
//!
//! Implements the consensus-specs `ssz/` specification. Hosts the persistent
//! tree-backed `SszList` / `SszVector` types used by `BeaconState` fields.
//!
//! Conformance: `consensus-specs/tests/formats/ssz_generic` and `ssz_static`.

mod array;
pub mod bitfield;
pub mod decode;
pub mod encode;
pub mod error;
pub mod gindex;
pub mod merkle_proof;
pub mod newtypes;
pub mod sequence;
pub mod tree_hash;
pub mod union;

#[cfg(test)]
mod proptest_eq;

pub use bitfield::{Bitlist, Bitvector};
pub use decode::{Decode, SszDecoder};
pub use encode::{BYTES_PER_LENGTH_OFFSET, Encode};
pub use error::SszError;
pub use gindex::{
    GeneralizedIndex, concat_generalized_indices, generalized_index_child,
    generalized_index_parent, generalized_index_sibling, get_generalized_index_bit,
    get_generalized_index_length,
};
pub use merkle_proof::{MerkleProof, build_single_proof_from_leaves, verify_merkle_proof};
pub use sequence::{SszList, SszSequence, SszVector};
pub use tree_hash::{
    TreeHash, TreeHashType, merkleize, merkleize_padded, mix_in_length, mix_in_selector,
    pack_bytes_to_chunks,
};
pub use union::SszUnion;

// Re-export the derive macros so users only need `pharos_ssz::Encode` etc.
pub use pharos_ssz_derive::{Decode, Encode, TreeHash};
// Re-export rayon so derive-emitted code resolves `::pharos_ssz::rayon::join`
// without requiring each consumer crate to add a direct rayon dependency.
pub use ::rayon;

/// Compile-fail guard: `derive(TreeHash)` on a struct whose fields are not
/// all `Send` must fail to compile, because the parallel emission (≥4 fields)
/// uses `rayon::join` closures that require `Send`. Match ONLY on the stable
/// error code `E0277` and substring `Send`/`Sync`, not the full sentence
/// (rustc's message text is not stable across toolchain versions). Hidden
/// from user-facing docs via `cfg(doctest)`.
///
/// ```compile_fail,E0277
/// use pharos_ssz::TreeHash;
/// use std::rc::Rc;
///
/// #[derive(TreeHash)]
/// struct NonSendFour {
///     a: u64,
///     b: u64,
///     c: u64,
///     d: Rc<u64>,  // !Send
/// }
///
/// let s = NonSendFour { a: 1, b: 2, c: 3, d: Rc::new(4) };
/// let _ = s.tree_hash_root();  // closure capturing `&Rc<u64>` is !Send
/// ```
#[cfg(doctest)]
pub struct NonSendDeriveTreeHashCompileFail;
