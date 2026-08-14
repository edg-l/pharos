//! SSZ error types.
//!
//! All decoding and encoding operations that can fail return `SszError`.

use thiserror::Error;

/// Errors that can occur during SSZ encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SszError {
    /// The byte slice has the wrong length for a fixed-size type.
    #[error("invalid byte length: found {found}, expected {expected}")]
    InvalidByteLength { found: usize, expected: usize },

    /// A `boolean` field contained a byte other than `0x00` or `0x01`.
    #[error("invalid boolean byte: 0x{0:02x}")]
    InvalidBoolByte(u8),

    /// A variable-length offset points outside the valid range.
    #[error("offset {offset} is out of range (max {max})")]
    OffsetOutOfRange { offset: usize, max: usize },

    /// Variable-length offsets are not monotonically increasing.
    #[error("offsets are not monotonically increasing")]
    OffsetsNotMonotonic,

    /// An offset points into the fixed-size region rather than the variable region.
    #[error("offset points into the fixed-size region")]
    OffsetIntoFixedRegion,

    /// The serialized form has extra trailing bytes that were not consumed.
    #[error("extra bytes: {extra} bytes remaining after decode")]
    ExtraBytes { extra: usize },

    /// The serialized form is shorter than required.
    #[error("incomplete data: needed {needed} bytes, found {found}")]
    IncompleteData { needed: usize, found: usize },

    /// A list's decoded length exceeds the declared limit `N`.
    #[error("list limit exceeded: len {len} > limit {limit}")]
    ListLimitExceeded { len: usize, limit: u64 },

    /// A fixed-length vector's decoded length does not match the expected length.
    #[error("vector length mismatch: found {found}, expected {expected}")]
    VectorLengthMismatch { found: usize, expected: usize },

    /// A `Bitlist` encoding is missing the mandatory sentinel length bit.
    #[error("bitlist is missing the mandatory length bit")]
    BitlistMissingLengthBit,

    /// A `Bitlist` encoding claims more bits than the declared limit `N`.
    #[error("bitlist overflow: encoded length exceeds limit {limit}")]
    BitlistOverflow { limit: u64 },

    /// A `Bitvector<N>` encoding has bits set beyond position `N-1` in the
    /// last byte. Per `simple-serialize.md`, these must be zero.
    #[error("bitvector has out-of-range bits set in its last byte")]
    InvalidBitvector,

    /// A custom error message for one-off conditions.
    #[error("{0}")]
    Custom(String),
}
