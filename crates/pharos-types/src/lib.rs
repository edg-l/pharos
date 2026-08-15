//! Pharos beacon-chain types.
//!
//! Per-fork containers organized as `enum`-of-forks (`BeaconState`,
//! `BeaconBlock`, `BeaconBlockBody`, ...). Preset constants live behind the
//! `EthSpec` trait (`MainnetEthSpec`, `MinimalEthSpec`, ...).
//!
//! # Phase-2 Tree-backend Decision Table
//!
//! Every `SszList` / `SszVector` field across all three `BeaconState` forks.
//! Decision rule: Tree if element is composite OR `T::PACKED_AS_FULL_CHUNK`
//! (currently only `FixedBytes<32>` / `Hash256` / `Root` / `Bytes32`).
//! Genuinely-packed multi-per-chunk basics (`u64`, `u8`, `bool`,
//! `FixedBytes<N<32>`) stay Naive; deferred to M11 per Task 1.3.
//!
//! ```text
//! Field                            | Element type       | Limit const              | Decision | Mutation rate     | Justification
//! ---------------------------------|--------------------|--------------------------|----------|-------------------|----------------------------------------------
//! phase0::block_roots              | Root=FixedBytes<32>| SLOTS_PER_HISTORICAL_ROOT| Tree     | every slot        | PACKED_AS_FULL_CHUNK; every-slot write = biggest win
//! phase0::state_roots              | Root=FixedBytes<32>| SLOTS_PER_HISTORICAL_ROOT| Tree     | every slot        | PACKED_AS_FULL_CHUNK; every-slot write = biggest win
//! phase0::historical_roots         | Root=FixedBytes<32>| HISTORICAL_ROOTS_LIMIT   | Tree     | ~once/8192 slots  | PACKED_AS_FULL_CHUNK; list grows infrequently
//! phase0::validators               | Validator          | VALIDATOR_REGISTRY_LIMIT | Tree     | per-epoch         | composite; amortised O(log N) CoW per epoch
//! phase0::randao_mixes             | Hash256=FixedBytes<32>| EPOCHS_PER_HISTORICAL_VECTOR| Tree | every epoch      | PACKED_AS_FULL_CHUNK
//! phase0::previous_epoch_attest.   | PendingAttestation | MAX_PENDING_ATTESTATIONS | Tree     | per-epoch flush   | composite
//! phase0::current_epoch_attest.    | PendingAttestation | MAX_PENDING_ATTESTATIONS | Tree     | per-block         | composite
//! phase0::balances                 | Gwei=u64           | VALIDATOR_REGISTRY_LIMIT | Naive    | per-epoch         | multi-per-chunk packed u64; deferred M11 (Task 1.3)
//! phase0::slashings                | Gwei=u64           | EPOCHS_PER_SLASHINGS_VECTOR| Naive  | rarely            | multi-per-chunk packed u64; deferred M11
//! phase0::eth1_data_votes          | Eth1Data           | ETH1_DATA_VOTES_LIMIT    | Naive    | per-block         | composite but small; not in hot-path hash loop
//! altair::block_roots              | Root=FixedBytes<32>| SLOTS_PER_HISTORICAL_ROOT| Tree     | every slot        | PACKED_AS_FULL_CHUNK
//! altair::state_roots              | Root=FixedBytes<32>| SLOTS_PER_HISTORICAL_ROOT| Tree     | every slot        | PACKED_AS_FULL_CHUNK
//! altair::historical_roots         | Root=FixedBytes<32>| HISTORICAL_ROOTS_LIMIT   | Tree     | ~once/8192 slots  | PACKED_AS_FULL_CHUNK
//! altair::validators               | Validator          | VALIDATOR_REGISTRY_LIMIT | Tree     | per-epoch         | composite
//! altair::randao_mixes             | Hash256=FixedBytes<32>| EPOCHS_PER_HISTORICAL_VECTOR| Tree| every epoch      | PACKED_AS_FULL_CHUNK
//! altair::balances                 | Gwei=u64           | VALIDATOR_REGISTRY_LIMIT | Naive    | per-epoch         | multi-per-chunk packed u64; deferred M11
//! altair::inactivity_scores        | u64                | VALIDATOR_REGISTRY_LIMIT | Naive    | per-epoch         | multi-per-chunk packed u64; deferred M11
//! altair::previous_epoch_particip. | ParticipationFlags=u8| VALIDATOR_REGISTRY_LIMIT| Naive   | per-epoch flush   | multi-per-chunk packed u8; deferred M11
//! altair::current_epoch_particip.  | ParticipationFlags=u8| VALIDATOR_REGISTRY_LIMIT| Naive   | per-block         | multi-per-chunk packed u8; deferred M11
//! bellatrix::block_roots           | Root=FixedBytes<32>| SLOTS_PER_HISTORICAL_ROOT| Tree     | every slot        | PACKED_AS_FULL_CHUNK
//! bellatrix::state_roots           | Root=FixedBytes<32>| SLOTS_PER_HISTORICAL_ROOT| Tree     | every slot        | PACKED_AS_FULL_CHUNK
//! bellatrix::historical_roots      | Root=FixedBytes<32>| HISTORICAL_ROOTS_LIMIT   | Tree     | ~once/8192 slots  | PACKED_AS_FULL_CHUNK
//! bellatrix::validators            | Validator          | VALIDATOR_REGISTRY_LIMIT | Tree     | per-epoch         | composite
//! bellatrix::randao_mixes          | Hash256=FixedBytes<32>| EPOCHS_PER_HISTORICAL_VECTOR| Tree| every epoch      | PACKED_AS_FULL_CHUNK
//! bellatrix::balances              | Gwei=u64           | VALIDATOR_REGISTRY_LIMIT | Naive    | per-epoch         | multi-per-chunk packed u64; deferred M11
//! bellatrix::inactivity_scores     | u64                | VALIDATOR_REGISTRY_LIMIT | Naive    | per-epoch         | multi-per-chunk packed u64; deferred M11
//! bellatrix::previous_epoch_part.  | ParticipationFlags=u8| VALIDATOR_REGISTRY_LIMIT| Naive   | per-epoch flush   | multi-per-chunk packed u8; deferred M11
//! bellatrix::current_epoch_part.   | ParticipationFlags=u8| VALIDATOR_REGISTRY_LIMIT| Naive   | per-block         | multi-per-chunk packed u8; deferred M11
//! ```
//!
//! Note: `previous_epoch_attestations` / `current_epoch_attestations` are phase0-only;
//! altair/bellatrix replace them with participation flags (Naive).
//! `Limit constants` (mainnet values):
//!   SLOTS_PER_HISTORICAL_ROOT = 8192, HISTORICAL_ROOTS_LIMIT = 16_777_216,
//!   VALIDATOR_REGISTRY_LIMIT = 1_099_511_627_776, EPOCHS_PER_HISTORICAL_VECTOR = 65536,
//!   EPOCHS_PER_SLASHINGS_VECTOR = 8192, MAX_PENDING_ATTESTATIONS = 4096.

pub mod altair;
pub mod bellatrix;
pub mod config;
pub mod eth_spec;
pub mod fork;
pub mod payload_status;
pub mod phase0;
pub mod shuffling;
pub mod state;
pub mod views;

pub use config::{ConfigError, RuntimeConfig, load_config_dir};
pub use eth_spec::{EthSpec, MainnetEthSpec, MinimalEthSpec};
pub use payload_status::PayloadStatus;
pub use state::{BeaconBlock, BeaconBlockBody, BeaconState, SignedBeaconBlock};
pub use views::{
    BeaconBlockBodyView, BeaconBlockView, BeaconStateView, LightClientFinalityUpdateView,
    LightClientOptimisticUpdateView, SignedBeaconBlockView,
};
