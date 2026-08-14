//! Test-only container types for the `ssz_generic/containers` handler.
//!
//! Definitions mirror the Python spec from
//! `tests/formats/ssz_generic/README.md`, with Rust SSZ equivalents:
//!
//! - `byte` / `uint8` → `u8`
//! - `uint16`        → `u16`
//! - `uint32`        → `u32` (unused directly but `FixedTestStruct.C`)
//! - `List[T, N]`    → `SszList<T, N>`
//! - `ByteList[N]`   → `SszList<u8, N>`
//! - `Vector[T, N]`  → `SszVector<T, N>`
//! - `Bitlist[N]`    → `Bitlist<N>`
//! - `Bitvector[N]`  → `Bitvector<N>`

use pharos_ssz::{Bitlist, Bitvector, Decode, Encode, SszList, SszVector, TreeHash};

// ── SingleFieldTestStruct ─────────────────────────────────────────────────────

/// `SingleFieldTestStruct` — one `byte` field.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SingleFieldTestStruct {
    pub a: u8,
}

// ── SmallTestStruct ───────────────────────────────────────────────────────────

/// `SmallTestStruct` — two `uint16` fields.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct SmallTestStruct {
    pub a: u16,
    pub b: u16,
}

// ── FixedTestStruct ───────────────────────────────────────────────────────────

/// `FixedTestStruct` — `uint8`, `uint64`, `uint32`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct FixedTestStruct {
    pub a: u8,
    pub b: u64,
    pub c: u32,
}

// ── VarTestStruct ─────────────────────────────────────────────────────────────

/// `VarTestStruct` — `uint16`, `List[uint16, 1024]`, `uint8`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct VarTestStruct {
    pub a: u16,
    pub b: SszList<u16, 1024>,
    pub c: u8,
}

// ── ComplexTestStruct ─────────────────────────────────────────────────────────

/// `ComplexTestStruct` — a mixture of variable and fixed fields.
///
/// ```python
/// class ComplexTestStruct(Container):
///     A: uint16
///     B: List[uint16, 128]
///     C: uint8
///     D: ByteList[256]
///     E: VarTestStruct
///     F: Vector[FixedTestStruct, 4]
///     G: Vector[VarTestStruct, 2]
/// ```
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ComplexTestStruct {
    pub a: u16,
    pub b: SszList<u16, 128>,
    pub c: u8,
    pub d: SszList<u8, 256>,
    pub e: VarTestStruct,
    pub f: SszVector<FixedTestStruct, 4>,
    pub g: SszVector<VarTestStruct, 2>,
}

// ── BitsStruct ────────────────────────────────────────────────────────────────

/// `BitsStruct` — mix of bitlists and bitvectors.
///
/// ```python
/// class BitsStruct(Container):
///     A: Bitlist[5]
///     B: Bitvector[2]
///     C: Bitvector[1]
///     D: Bitlist[6]
///     E: Bitvector[8]
/// ```
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct BitsStruct {
    pub a: Bitlist<5>,
    pub b: Bitvector<2>,
    pub c: Bitvector<1>,
    pub d: Bitlist<6>,
    pub e: Bitvector<8>,
}
