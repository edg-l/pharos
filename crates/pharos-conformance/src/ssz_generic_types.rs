//! Test-only container types for the `ssz_generic/containers` handler and
//! progressive-container / compatible-union handlers.
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
//! - `ProgressiveList[T]` → `ProgressiveList<T>`
//! - `ProgressiveBitlist` → `ProgressiveBitlist`
//!
//! Progressive containers (EIP-7495) and compatible unions (EIP-7495) are
//! declared in this file and used by the `progressive_containers` and
//! `compatible_unions` conformance handlers in `ssz_generic.rs`.

use pharos_ssz::{
    Bitlist, Bitvector, CompatibleUnion, CompatibleUnionValue, Decode, Encode, ProgressiveBitlist,
    ProgressiveList, SszError, SszList, SszVector, TreeHash, TreeHashType, merkleize_progressive,
    mix_in_active_fields,
};
use pharos_utils::Hash256;

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

// ── ProgressiveTestStruct (containers/ subcat) ────────────────────────────────

/// `ProgressiveTestStruct` — regular container with ProgressiveList fields.
///
/// ```python
/// class ProgressiveTestStruct(Container):
///     A: ProgressiveList[byte]
///     B: ProgressiveList[uint64]
///     C: ProgressiveList[SmallTestStruct]
///     D: ProgressiveList[ProgressiveList[VarTestStruct]]
/// ```
///
/// This is a regular SSZ container (Encode/Decode via standard rules),
/// but the fields happen to be ProgressiveList types. The hash_tree_root
/// uses the standard container rule: `merkleize([field roots...])`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgressiveTestStruct {
    pub a: ProgressiveList<u8>,
    pub b: ProgressiveList<u64>,
    pub c: ProgressiveList<SmallTestStruct>,
    pub d: ProgressiveList<ProgressiveList<VarTestStruct>>,
}

// ── ProgressiveBitsStruct (containers/ subcat) ────────────────────────────────

/// `ProgressiveBitsStruct` — regular container with ProgressiveBitlist fields.
///
/// ```python
/// class ProgressiveBitsStruct(Container):
///     A: Bitvector[256]
///     B: Bitlist[256]
///     C: ProgressiveBitlist
///     D: Bitvector[257]
///     E: Bitlist[257]
///     F: ProgressiveBitlist
///     G: Bitvector[1280]
///     H: Bitlist[1280]
///     I: ProgressiveBitlist
///     J: Bitvector[1281]
///     K: Bitlist[1281]
///     L: ProgressiveBitlist
/// ```
///
/// This is a regular SSZ container; hash_tree_root uses the standard rule.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgressiveBitsStruct {
    pub a: Bitvector<256>,
    pub b: Bitlist<256>,
    pub c: ProgressiveBitlist,
    pub d: Bitvector<257>,
    pub e: Bitlist<257>,
    pub f: ProgressiveBitlist,
    pub g: Bitvector<1280>,
    pub h: Bitlist<1280>,
    pub i: ProgressiveBitlist,
    pub j: Bitvector<1281>,
    pub k: Bitlist<1281>,
    pub l: ProgressiveBitlist,
}

// ── Progressive container helper ─────────────────────────────────────────────

/// Compute the progressive-container `hash_tree_root`.
///
/// Algorithm (EIP-7495):
///   1. Build a chunk slice of length `len(active_fields)`.
///      - At each `active_fields[i] == 1` position: `hash_tree_root(field_i)`.
///      - At each `active_fields[i] == 0` position: `Bytes32()` (zero hash).
///   2. `root = merkleize_progressive(chunks, 1)`.
///   3. `mix_in_active_fields(root, active_fields)`.
fn progressive_container_root(
    field_roots: &[(usize, Hash256)],
    active_fields_len: usize,
    active_fields: &[bool],
) -> Hash256 {
    debug_assert_eq!(active_fields.len(), active_fields_len);
    let mut chunks = vec![Hash256::default(); active_fields_len];
    for &(slot, root) in field_roots {
        chunks[slot] = root;
    }
    let prog_root = merkleize_progressive(&chunks, 1);
    mix_in_active_fields(prog_root, active_fields)
}

// ── ProgressiveSingleFieldContainerTestStruct ─────────────────────────────────

/// ```python
/// class ProgressiveSingleFieldContainerTestStruct(
///     ProgressiveContainer(active_fields=[1])
/// ):
///     A: byte
/// ```
///
/// active_fields = [1] — A is at slot 0.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgressiveSingleFieldContainerTestStruct {
    pub a: u8,
}

impl TreeHash for ProgressiveSingleFieldContainerTestStruct {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        const ACTIVE_FIELDS: [bool; 1] = [true];
        let root_a = self.a.tree_hash_root();
        progressive_container_root(&[(0, root_a)], 1, &ACTIVE_FIELDS)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("progressive container is never packed")
    }
}

// ── ProgressiveSingleListContainerTestStruct ──────────────────────────────────

/// ```python
/// class ProgressiveSingleListContainerTestStruct(
///     ProgressiveContainer(active_fields=[0, 0, 0, 0, 1])
/// ):
///     C: ProgressiveBitlist
/// ```
///
/// active_fields = [0, 0, 0, 0, 1] — C is at slot 4.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgressiveSingleListContainerTestStruct {
    pub c: ProgressiveBitlist,
}

impl TreeHash for ProgressiveSingleListContainerTestStruct {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        const ACTIVE_FIELDS: [bool; 5] = [false, false, false, false, true];
        let root_c = self.c.tree_hash_root();
        progressive_container_root(&[(4, root_c)], 5, &ACTIVE_FIELDS)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("progressive container is never packed")
    }
}

// ── ProgressiveVarTestStruct ──────────────────────────────────────────────────

/// ```python
/// class ProgressiveVarTestStruct(
///     ProgressiveContainer(active_fields=[1, 0, 1, 0, 1])
/// ):
///     A: byte
///     B: List[uint16, 123]
///     C: ProgressiveBitlist
/// ```
///
/// active_fields = [1, 0, 1, 0, 1] — A at slot 0, B at slot 2, C at slot 4.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgressiveVarTestStruct {
    pub a: u8,
    pub b: SszList<u16, 123>,
    pub c: ProgressiveBitlist,
}

impl TreeHash for ProgressiveVarTestStruct {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        const ACTIVE_FIELDS: [bool; 5] = [true, false, true, false, true];
        let root_a = self.a.tree_hash_root();
        let root_b = self.b.tree_hash_root();
        let root_c = self.c.tree_hash_root();
        progressive_container_root(&[(0, root_a), (2, root_b), (4, root_c)], 5, &ACTIVE_FIELDS)
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("progressive container is never packed")
    }
}

// ── ProgressiveComplexTestStruct ──────────────────────────────────────────────

/// ```python
/// class ProgressiveComplexTestStruct(
///     ProgressiveContainer(
///         active_fields=[1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1]
///     )
/// ):
///     A: byte
///     B: List[uint16, 123]
///     C: ProgressiveBitlist
///     D: ProgressiveList[uint64]
///     E: ProgressiveList[SmallTestStruct]
///     F: ProgressiveList[ProgressiveList[VarTestStruct]]
///     G: List[ProgressiveSingleFieldContainerTestStruct, 10]
///     H: ProgressiveList[ProgressiveVarTestStruct]
/// ```
///
/// active_fields = [1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1]
/// Field → slot: A→0, B→2, C→4, D→8, E→12, F→13, G→20, H→21
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgressiveComplexTestStruct {
    pub a: u8,
    pub b: SszList<u16, 123>,
    pub c: ProgressiveBitlist,
    pub d: ProgressiveList<u64>,
    pub e: ProgressiveList<SmallTestStruct>,
    pub f: ProgressiveList<ProgressiveList<VarTestStruct>>,
    pub g: SszList<ProgressiveSingleFieldContainerTestStruct, 10>,
    pub h: ProgressiveList<ProgressiveVarTestStruct>,
}

impl TreeHash for ProgressiveComplexTestStruct {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        // active_fields = [1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1]
        const ACTIVE_FIELDS: [bool; 22] = [
            true, false, true, false, true, false, false, false, true, false, false, false, true,
            true, false, false, false, false, false, false, true, true,
        ];
        let root_a = self.a.tree_hash_root();
        let root_b = self.b.tree_hash_root();
        let root_c = self.c.tree_hash_root();
        let root_d = self.d.tree_hash_root();
        let root_e = self.e.tree_hash_root();
        let root_f = self.f.tree_hash_root();
        let root_g = self.g.tree_hash_root();
        let root_h = self.h.tree_hash_root();
        progressive_container_root(
            &[
                (0, root_a),
                (2, root_b),
                (4, root_c),
                (8, root_d),
                (12, root_e),
                (13, root_f),
                (20, root_g),
                (21, root_h),
            ],
            22,
            &ACTIVE_FIELDS,
        )
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("progressive container is never packed")
    }
}

// ── CompatibleUnion type options ──────────────────────────────────────────────

/// The data value inside a `CompatibleUnionA`, `CompatibleUnionBC`, or
/// `CompatibleUnionABCA` union. The variant includes the selector so that
/// re-encoding and root computation are self-contained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnionAbcaData {
    /// selector=1: `ProgressiveSingleFieldContainerTestStruct`
    Sel1(ProgressiveSingleFieldContainerTestStruct),
    /// selector=2: `ProgressiveSingleListContainerTestStruct`
    Sel2(ProgressiveSingleListContainerTestStruct),
    /// selector=3: `ProgressiveVarTestStruct`
    Sel3(ProgressiveVarTestStruct),
    /// selector=4: `ProgressiveSingleFieldContainerTestStruct` (same type as 1)
    Sel4(ProgressiveSingleFieldContainerTestStruct),
}

impl CompatibleUnionValue for UnionAbcaData {
    fn from_selector_and_bytes(selector: u8, data: &[u8]) -> Result<Self, SszError> {
        match selector {
            1 => Ok(Self::Sel1(
                ProgressiveSingleFieldContainerTestStruct::from_ssz_bytes(data)?,
            )),
            2 => Ok(Self::Sel2(
                ProgressiveSingleListContainerTestStruct::from_ssz_bytes(data)?,
            )),
            3 => Ok(Self::Sel3(ProgressiveVarTestStruct::from_ssz_bytes(data)?)),
            4 => Ok(Self::Sel4(
                ProgressiveSingleFieldContainerTestStruct::from_ssz_bytes(data)?,
            )),
            _ => Err(SszError::Custom(format!(
                "UnionAbcaData: unknown selector {selector}"
            ))),
        }
    }

    fn data_ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Sel1(v) => v.ssz_append(buf),
            Self::Sel2(v) => v.ssz_append(buf),
            Self::Sel3(v) => v.ssz_append(buf),
            Self::Sel4(v) => v.ssz_append(buf),
        }
    }

    fn data_tree_hash_root(&self) -> Hash256 {
        match self {
            Self::Sel1(v) => v.tree_hash_root(),
            Self::Sel2(v) => v.tree_hash_root(),
            Self::Sel3(v) => v.tree_hash_root(),
            Self::Sel4(v) => v.tree_hash_root(),
        }
    }

    fn selector(&self) -> u8 {
        match self {
            Self::Sel1(_) => 1,
            Self::Sel2(_) => 2,
            Self::Sel3(_) => 3,
            Self::Sel4(_) => 4,
        }
    }
}

/// `CompatibleUnionA = CompatibleUnion({1: ProgressiveSingleFieldContainerTestStruct})`
///
/// Only selector=1 is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnionAData {
    Sel1(ProgressiveSingleFieldContainerTestStruct),
}

impl CompatibleUnionValue for UnionAData {
    fn from_selector_and_bytes(selector: u8, data: &[u8]) -> Result<Self, SszError> {
        match selector {
            1 => Ok(Self::Sel1(
                ProgressiveSingleFieldContainerTestStruct::from_ssz_bytes(data)?,
            )),
            _ => Err(SszError::Custom(format!(
                "UnionAData: unknown selector {selector}"
            ))),
        }
    }

    fn data_ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Sel1(v) => v.ssz_append(buf),
        }
    }

    fn data_tree_hash_root(&self) -> Hash256 {
        match self {
            Self::Sel1(v) => v.tree_hash_root(),
        }
    }

    fn selector(&self) -> u8 {
        match self {
            Self::Sel1(_) => 1,
        }
    }
}

/// `CompatibleUnionBC = CompatibleUnion({2: PSL, 3: PVar})`
///
/// Only selectors 2 and 3 are valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnionBcData {
    Sel2(ProgressiveSingleListContainerTestStruct),
    Sel3(ProgressiveVarTestStruct),
}

impl CompatibleUnionValue for UnionBcData {
    fn from_selector_and_bytes(selector: u8, data: &[u8]) -> Result<Self, SszError> {
        match selector {
            2 => Ok(Self::Sel2(
                ProgressiveSingleListContainerTestStruct::from_ssz_bytes(data)?,
            )),
            3 => Ok(Self::Sel3(ProgressiveVarTestStruct::from_ssz_bytes(data)?)),
            _ => Err(SszError::Custom(format!(
                "UnionBcData: unknown selector {selector}"
            ))),
        }
    }

    fn data_ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Sel2(v) => v.ssz_append(buf),
            Self::Sel3(v) => v.ssz_append(buf),
        }
    }

    fn data_tree_hash_root(&self) -> Hash256 {
        match self {
            Self::Sel2(v) => v.tree_hash_root(),
            Self::Sel3(v) => v.tree_hash_root(),
        }
    }

    fn selector(&self) -> u8 {
        match self {
            Self::Sel2(_) => 2,
            Self::Sel3(_) => 3,
        }
    }
}

/// Type aliases for the three test union types from the spec.
pub type CompatibleUnionA = CompatibleUnion<UnionAData>;
pub type CompatibleUnionBC = CompatibleUnion<UnionBcData>;
pub type CompatibleUnionABCA = CompatibleUnion<UnionAbcaData>;
