//! Fuzz target: req-resp varint + SSZ-snappy codec on arbitrary bytes.
//!
//! Oracle: feeding arbitrary bytes through the req-resp codec's decode helpers
//! must never panic — only return `Err`.
//!
//! Exercises:
//! - `read_varint` (LEB128 varint parser)
//! - `decode_snappy_frame` (streaming snappy used in req-resp)
//! - `decode_snappy_block` (raw snappy used in gossip)
//! - SSZ decode of request types after simulated snappy decode
#![no_main]

use futures::io::Cursor;
use libfuzzer_sys::fuzz_target;
use pharos_network::{
    codec::{
        snappy_block::decode_snappy_block,
        snappy_frame::{MAX_PAYLOAD_SIZE, decode_snappy_frame},
    },
    rpc::varint::read_varint,
};
use pharos_ssz::Decode;
use pharos_types::phase0::{BeaconBlocksByRangeRequest, Status};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // ── 1. Varint reader ────────────────────────────────────────────────────
    // Drive the async varint reader synchronously via futures::executor.
    let _ = futures::executor::block_on(async {
        let mut cursor = Cursor::new(data);
        read_varint(&mut cursor).await
    });

    // ── 2. Snappy-frame decode (req-resp format) ────────────────────────────
    let _ = decode_snappy_frame(data, MAX_PAYLOAD_SIZE);

    // ── 3. Snappy-block decode (gossip format) ──────────────────────────────
    let _ = decode_snappy_block(data, MAX_PAYLOAD_SIZE);

    // ── 4. Simulated req-resp pipeline: snappy-frame → SSZ ─────────────────
    // Attempt to frame-decode then SSZ-decode common request types.
    // This exercises the full decode path that a malicious peer could send.
    if let Ok(decompressed) = decode_snappy_frame(data, MAX_PAYLOAD_SIZE) {
        // Status message (84 bytes)
        let _ = Status::from_ssz_bytes(&decompressed);
        // BeaconBlocksByRange request (24 bytes)
        let _ = BeaconBlocksByRangeRequest::from_ssz_bytes(&decompressed);
    }

    // ── 5. Simulated gossip pipeline: snappy-block → SSZ ───────────────────
    if let Ok(decompressed) = decode_snappy_block(data, MAX_PAYLOAD_SIZE) {
        let _ = Status::from_ssz_bytes(&decompressed);
        let _ = BeaconBlocksByRangeRequest::from_ssz_bytes(&decompressed);
    }
});
