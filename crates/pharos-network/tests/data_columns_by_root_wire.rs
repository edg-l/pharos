//! Wire-byte fixture test for the Fulu `DataColumnSidecarsByRoot` request
//! (OQ3 / RI-7 of the M13-Fulu plan, task 5.9).
//!
//! The request is `List[DataColumnsByRootIdentifier, MAX_REQUEST_BLOCKS_DENEB]`
//! — a CONTAINER list whose element (`DataColumnsByRootIdentifier`) is itself a
//! variable-size container (it holds a `List[ColumnIndex, NUMBER_OF_COLUMNS]`).
//! Per SSZ, a list of variable-size elements serializes as a 4-byte offset
//! table followed by the concatenated element encodings. A wire observer
//! therefore sees a leading 4-byte offset prefix.
//!
//! This is the OPPOSITE of the `D-blocksbyroot-bare-list` trap
//! (`blocks_by_root_request_is_bare_list_no_offset` in `pharos-types`), where
//! the request is a bare `List[Root, N]` of FIXED-size elements with NO offset.
//! Conflating the two cost a -100 ban from a reference CL client in M5-follow, hence this
//! explicit assertion rather than an assumption.

use pharos_ssz::{Encode, SszList};
use pharos_types::fulu::{DataColumnSidecarsByRootRequest, DataColumnsByRootIdentifier};
use pharos_utils::Hash256;

type Req = DataColumnSidecarsByRootRequest<128, 128>;
type Ident = DataColumnsByRootIdentifier<128>;

/// Encode a two-entry `DataColumnSidecarsByRootRequest` and assert the wire
/// bytes carry the 4-byte offset prefix of a variable-element container list.
#[test]
fn data_columns_by_root_request_is_container_list_no_offset() {
    // Empty request: a list of zero variable-size elements is zero bytes (no
    // offset table when there are no elements).
    let empty = Req::default();
    assert_eq!(
        empty.as_ssz_bytes().len(),
        0,
        "empty DataColumnSidecarsByRoot request must be 0 bytes"
    );

    // Two identifiers, each with two column indices.
    let id0 = Ident {
        block_root: Hash256::from([0x11u8; 32]),
        columns: SszList::from_vec(vec![0u64, 1u64]).unwrap(),
    };
    let id1 = Ident {
        block_root: Hash256::from([0x22u8; 32]),
        columns: SszList::from_vec(vec![5u64, 9u64]).unwrap(),
    };
    let req = Req {
        ids: SszList::from_vec(vec![id0.clone(), id1.clone()]).unwrap(),
    };
    let encoded = req.as_ssz_bytes();

    // A single `DataColumnsByRootIdentifier` with two columns encodes as:
    //   block_root (32) + offset(4) for the `columns` list + columns (2 * 8 = 16)
    //   = 52 bytes.
    let ident_len = id0.as_ssz_bytes().len();
    assert_eq!(ident_len, 52, "identifier with 2 columns must be 52 bytes");

    // The list of TWO variable-size identifiers serializes as:
    //   [offset0:4][offset1:4] (offset table) ++ ident0 ++ ident1
    //   = 8 (offsets) + 52 + 52 = 112 bytes.
    assert_eq!(
        encoded.len(),
        8 + ident_len * 2,
        "two-identifier request must be offset-table (8) + 2 idents"
    );

    // The FIRST 4 bytes MUST be the offset prefix (a u32 little-endian pointing
    // past the 2-entry offset table, i.e. value 8). This is the container-list
    // shape — NOT the bare-list shape (which would start directly with the
    // first element's bytes and have NO offset prefix).
    let first_offset = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
    assert_eq!(
        first_offset, 8,
        "first 4 bytes must be the offset prefix (= 8, past the 2-entry offset table)"
    );

    // The bytes immediately after the offset table must be id0's encoding (the
    // 32-byte block_root first), confirming the offset points at the elements.
    assert_eq!(
        &encoded[8..40],
        id0.block_root.as_slice(),
        "bytes after the offset table must begin with id0.block_root"
    );

    // Round-trip back through the request decoder.
    use pharos_ssz::Decode;
    let decoded = Req::from_ssz_bytes(&encoded).expect("decode DataColumnSidecarsByRoot request");
    assert_eq!(decoded, req, "request must round-trip");
}
