//! Reproduces the live electra block-production signature failure.
//!
//! Mirrors the LIVE path precisely:
//!   BN produce: SSZ-encode the concrete electra `SignedBeaconBlock`, return
//!               `[disc=0x05] ++ ssz_bytes[100..]` to the VC.
//!   VC sign:    decode that as the fork-enum `MinimalBeaconBlock`, compute
//!               `tree_hash_root()` (the VC-side proposer object root).
//!   STF verify: decode `[disc] ++ ssz_bytes` (sig overlaid) as the fork-enum
//!               `MinimalSignedBeaconBlock`, take `.message().tree_hash_root()`.
//!
//! Asserts the two roots match. If they differ, the proposer signature can never
//! verify on import (StateTransitionError::InvalidBlockSignature).

use pharos_ssz::{Bitlist, Bitvector, Decode as _, Encode as _, SszList, TreeHash};
use pharos_types::electra::attestation::Attestation as ElectraAttestation;
use pharos_types::electra::requests::{DepositRequest, ExecutionRequests};
use pharos_types::electra::{MinimalBeaconBlock, MinimalSignedBeaconBlock};
use pharos_types::phase0::primitives::{CommitteeIndex, Root, Slot, ValidatorIndex};
use pharos_types::state::{
    BeaconBlock as ForkBeaconBlock, SignedBeaconBlock as ForkSignedBeaconBlock,
};

type MinForkBeaconBlock = ForkBeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
    8192,
    4,
    8192,
    16,
    2,
>;
type MinForkSignedBeaconBlock = ForkSignedBeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
    8192,
    4,
    8192,
    16,
    2,
>;

#[test]
fn electra_vc_and_stf_signing_roots_match() {
    // Build a concrete minimal electra signed block with non-trivial
    // variable-length electra fields (EIP-7549 attestation + EIP-7685 requests).
    let mut block = MinimalBeaconBlock::default();
    block.slot = Slot(40);
    block.proposer_index = ValidatorIndex(7);
    block.parent_root = Root::from_array([0xAB; 32]);
    block.state_root = Root::from_array([0xCD; 32]);

    // EIP-7549 attestation: aggregation_bits + committee_bits set.
    let mut agg_bits = Bitlist::<8192>::with_capacity(3);
    for _ in 0..3 {
        let _ = agg_bits.push(true);
    }
    let mut committee_bits = Bitvector::<4>::new();
    committee_bits.set(1, true);
    let mut att = ElectraAttestation::<8192, 4>::default();
    att.aggregation_bits = agg_bits;
    att.committee_bits = committee_bits;
    att.data.index = CommitteeIndex(0);
    block.body.attestations = SszList::from_items(vec![att]).unwrap();

    // EIP-7685 execution_requests: one deposit request.
    let mut reqs = ExecutionRequests::<8192, 16, 2>::default();
    let dep = DepositRequest::default();
    reqs.deposits = SszList::from_items(vec![dep]).unwrap();
    block.body.execution_requests = reqs;

    let signed = MinimalSignedBeaconBlock {
        message: block.clone(),
        signature: pharos_utils::BLSSignature::from([0x11u8; 96]),
    };

    // ── BN produce path: SSZ-encode, slice [100..], prepend disc ──────────────
    let ssz_bytes = signed.as_ssz_bytes();
    assert!(ssz_bytes.len() >= 100, "ssz too short");

    // Verify the offset embedded at bytes [0..4] really is 100.
    let embedded_offset = u32::from_le_bytes(ssz_bytes[0..4].try_into().unwrap());
    assert_eq!(
        embedded_offset, 100,
        "SignedBeaconBlock message offset must be 100 (4 offset + 96 sig)"
    );

    let mut vc_bytes = Vec::with_capacity(1 + ssz_bytes.len() - 100);
    vc_bytes.push(0x05u8);
    vc_bytes.extend_from_slice(&ssz_bytes[100..]);

    // ── VC sign path: decode fork-enum BeaconBlock, tree_hash_root ────────────
    let vc_block = MinForkBeaconBlock::from_ssz_bytes(&vc_bytes)
        .expect("VC decode of [disc]++ssz[100..] as fork-enum BeaconBlock");
    let vc_root = vc_block.tree_hash_root();

    // ── STF verify path: decode full fork-enum SignedBeaconBlock, message root ─
    let mut full = Vec::with_capacity(1 + ssz_bytes.len());
    full.push(0x05u8);
    full.extend_from_slice(&ssz_bytes);
    let stf_signed = MinForkSignedBeaconBlock::from_ssz_bytes(&full)
        .expect("STF decode of [disc]++ssz as fork-enum SignedBeaconBlock");
    // The STF dispatches on the variant and runs the concrete electra
    // state_transition, which hashes `signed_block.message()` (concrete).
    let stf_root = match &stf_signed {
        ForkSignedBeaconBlock::Electra(inner) => inner.message.tree_hash_root(),
        _ => panic!("STF decode produced a non-electra variant"),
    };

    // Ground truth: the concrete block the STF actually post-processes.
    let concrete_root = block.tree_hash_root();

    eprintln!("concrete message root : {concrete_root:?}");
    eprintln!("vc-side root          : {vc_root:?}");
    eprintln!("stf-side root         : {stf_root:?}");

    assert_eq!(
        stf_root, concrete_root,
        "STF fork-enum message root must equal concrete electra message root"
    );
    assert_eq!(
        vc_root, concrete_root,
        "VC fork-enum BeaconBlock root (from ssz[100..]) must equal concrete electra message root"
    );
    assert_eq!(
        vc_root, stf_root,
        "VC signing root and STF verifying root must match, else the proposer signature fails"
    );
}
