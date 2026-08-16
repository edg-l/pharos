//! Error types for the conformance harness.

use pharos_ssz::SszError;

#[derive(thiserror::Error, Debug)]
pub enum ConformanceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(String),
    #[error("snappy: {0}")]
    Snappy(String),
    #[error("ssz: {0}")]
    Ssz(#[from] SszError),
    #[error("encode round-trip mismatch in {case}: got {got_hex}, want {want_hex}")]
    EncodeRoundTrip {
        case: String,
        got_hex: String,
        want_hex: String,
    },
    #[error("hash_tree_root mismatch in {case}: got {got}, want {want}")]
    HashTreeRoot {
        case: String,
        got: String,
        want: String,
    },
    #[error("unsupported handler {0}")]
    UnsupportedHandler(String),
    #[error("malformed fixture: {0}")]
    MalformedFixture(String),
    #[error("unknown ssz_static type `{type_name}` in {fork}/{preset}")]
    UnknownSszStaticType {
        fork: String,
        preset: String,
        type_name: String,
    },
    #[error("unknown ssz_generic uint size in suite `{suite}`")]
    UnknownUintSize { suite: String },
    #[error("unknown ssz_generic basic_vector length {n} for element `{elem}`")]
    UnknownVecLength { elem: String, n: u64 },
    #[error("unknown ssz_generic basic_vector element type `{elem}`")]
    UnknownVecElemType { elem: String },
    #[error("unknown ssz_generic bitvector length {n}")]
    UnknownBitvectorLength { n: u64 },
    #[error("unknown ssz_generic bitlist limit {n}")]
    UnknownBitlistLimit { n: u64 },
    #[error("unknown ssz_generic container struct `{name}`")]
    UnknownContainerStruct { name: String },
}
