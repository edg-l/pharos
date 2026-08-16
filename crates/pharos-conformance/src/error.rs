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
}
