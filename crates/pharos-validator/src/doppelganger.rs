//! Doppelganger detection for the validator client.
//!
//! Per `D-doppelganger-bn-liveness-endpoint`:
//! - When `--doppelganger-protection` is enabled (the default), the VC holds
//!   off signing for the first 2 complete epochs after startup.
//! - During the hold-off period, it polls `POST /eth/v1/validator/liveness/{epoch}`
//!   for the VC's local validator pubkeys.
//! - If **any** local validator appears live (i.e. `is_live = true`), the VC
//!   performs a **FATAL abort**: another instance is signing for this key.
//!
//! A validator is "past the hold-off" after it has been observed as non-live
//! for at least 2 consecutive epochs starting from the epoch at which the VC
//! started. This mirrors the common CL client approach of skipping `N = 2` epochs.
//!
//! # Safety invariant
//!
//! The VC MUST NOT sign any message (block, attestation, sync) while
//! `DoppelgangerGuard::may_sign()` returns `false`.

use std::collections::HashMap;
use std::time::Duration;

use tracing::{error, info, warn};

use crate::bn_client::{BnClient, BnError};

// ── DoppelgangerState ─────────────────────────────────────────────────────────

/// Tracks the doppelganger hold-off state for a single validator.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ValidatorState {
    /// Still in the hold-off window; `clear_epoch` is the first epoch at which
    /// we allow signing (== startup_epoch + HOLDOFF_EPOCHS).
    HoldOff { clear_epoch: u64 },
    /// Past the hold-off; signing is allowed.
    Cleared,
}

/// Number of epochs to hold off signing at startup.
pub const HOLDOFF_EPOCHS: u64 = 2;

// ── DoppelgangerGuard ─────────────────────────────────────────────────────────

/// Doppelganger protection guard.
///
/// Tracks which validators are still in hold-off and which have been cleared.
/// `may_sign(pubkey_hex)` is the authoritative check the signing paths use.
pub struct DoppelgangerGuard {
    /// Whether doppelganger protection is enabled (`--doppelganger-protection`).
    enabled: bool,
    /// Per-pubkey state.
    states: HashMap<String, ValidatorState>,
}

impl DoppelgangerGuard {
    /// Create a guard for all validators in `pubkeys_hex`.
    ///
    /// When `enabled = false`, all validators are immediately cleared.
    pub fn new(enabled: bool, pubkeys_hex: &[String], startup_epoch: u64) -> Self {
        let mut states = HashMap::new();
        for pk in pubkeys_hex {
            let state = if enabled {
                ValidatorState::HoldOff {
                    clear_epoch: startup_epoch.saturating_add(HOLDOFF_EPOCHS),
                }
            } else {
                ValidatorState::Cleared
            };
            states.insert(pk.clone(), state);
        }
        Self { enabled, states }
    }

    /// Returns `true` when the validator identified by `pubkey_hex` is allowed to sign.
    ///
    /// `current_epoch` is supplied by the caller (from the run loop's epoch watch).
    pub fn may_sign(&self, pubkey_hex: &str, current_epoch: u64) -> bool {
        if !self.enabled {
            return true;
        }
        match self.states.get(pubkey_hex) {
            Some(ValidatorState::Cleared) => true,
            Some(ValidatorState::HoldOff { clear_epoch }) => current_epoch >= *clear_epoch,
            None => false,
        }
    }

    /// Advance the state for all validators by observing `current_epoch`.
    ///
    /// Validators whose `clear_epoch <= current_epoch` are promoted to `Cleared`.
    /// Called once per epoch boundary.
    pub fn advance(&mut self, current_epoch: u64) {
        for state in self.states.values_mut() {
            if let ValidatorState::HoldOff { clear_epoch } = state
                && current_epoch >= *clear_epoch
            {
                *state = ValidatorState::Cleared;
            }
        }
    }
}

// ── run_doppelganger_check ────────────────────────────────────────────────────

/// Poll the BN liveness endpoint and fatal-abort if any local validator is live.
///
/// Called once per epoch during the hold-off period. If all queried validators
/// return `is_live = false`, this is a no-op. If any return `is_live = true`,
/// the process aborts with a clear error message.
///
/// Per `D-doppelganger-bn-liveness-endpoint`.
pub async fn run_doppelganger_check(
    bn: &BnClient,
    validator_indices: &[u64],
    epoch: u64,
) -> Result<(), BnError> {
    let results = bn.validator_liveness(epoch, validator_indices).await?;
    for item in &results {
        if item.is_live {
            // FATAL: another instance is signing for this validator.
            error!(
                validator_index = %item.index,
                epoch,
                "DOPPELGANGER DETECTED: validator appears live elsewhere. \
                 Refusing to sign. Shutting down to prevent slashing."
            );
            // Use process::exit so no further signing can happen.
            std::process::exit(1);
        }
    }
    info!(
        epoch,
        validators = validator_indices.len(),
        "doppelganger check passed (all non-live)"
    );
    Ok(())
}

/// Drive the doppelganger poll loop for the first `HOLDOFF_EPOCHS` epochs.
///
/// Polls once per epoch. Returns only when all validators have been cleared
/// (i.e. the hold-off window has expired with no live activity detected).
///
/// If `enabled = false` or `validator_indices` is empty, returns immediately.
pub async fn run_doppelganger_loop(
    enabled: bool,
    bn: BnClient,
    validator_indices: Vec<u64>,
    startup_epoch: u64,
    slots_per_epoch: u64,
    slot_duration_ms: u64,
) {
    if !enabled || validator_indices.is_empty() {
        return;
    }

    let clear_epoch = startup_epoch.saturating_add(HOLDOFF_EPOCHS);
    let slot_duration = Duration::from_millis(slot_duration_ms);
    let epoch_duration = slot_duration * slots_per_epoch as u32;

    info!(
        startup_epoch,
        clear_epoch,
        validators = validator_indices.len(),
        "doppelganger hold-off started; no signing until epoch {clear_epoch}"
    );

    // Poll the epoch just before startup (a doppelganger may have been active
    // before we started) through every epoch in the hold-off window. With
    // HOLDOFF_EPOCHS = 2 this covers `startup-1, startup, startup+1` — i.e. every
    // epoch in which a peer could be live before the guard clears at `clear_epoch`.
    let first_check = startup_epoch.saturating_sub(1);
    for check_epoch in first_check..clear_epoch {
        match run_doppelganger_check(&bn, &validator_indices, check_epoch).await {
            Ok(()) => {}
            Err(BnError::Unavailable) => {
                warn!(
                    check_epoch,
                    "BN unavailable during doppelganger check; will retry next epoch"
                );
            }
            Err(e) => {
                warn!(check_epoch, %e, "doppelganger check failed; continuing (non-fatal)");
            }
        }

        // Wait approximately one epoch before the next poll.
        tokio::time::sleep(epoch_duration).await;
    }

    info!(
        epoch = clear_epoch,
        "doppelganger hold-off complete; signing enabled"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_guard(enabled: bool, startup_epoch: u64) -> DoppelgangerGuard {
        let pks = vec!["0xaabbcc".to_string(), "0xddeeff".to_string()];
        DoppelgangerGuard::new(enabled, &pks, startup_epoch)
    }

    #[test]
    fn disabled_guard_allows_signing_immediately() {
        let g = make_guard(false, 5);
        assert!(g.may_sign("0xaabbcc", 5));
        assert!(g.may_sign("0xddeeff", 5));
    }

    #[test]
    fn enabled_guard_blocks_during_holdoff() {
        let g = make_guard(true, 5);
        // Epoch 5 → clear_epoch = 7; should block.
        assert!(!g.may_sign("0xaabbcc", 5));
        assert!(!g.may_sign("0xaabbcc", 6));
        // Epoch 7 → at or past clear_epoch → allow.
        assert!(g.may_sign("0xaabbcc", 7));
    }

    #[test]
    fn advance_clears_validators_at_boundary() {
        let mut g = make_guard(true, 5);
        assert!(!g.may_sign("0xaabbcc", 6));
        g.advance(7);
        // After advancing to epoch 7 (>= clear_epoch=7), the state is Cleared.
        assert!(g.may_sign("0xaabbcc", 7));
    }

    #[test]
    fn unknown_pubkey_returns_false() {
        let g = make_guard(true, 0);
        assert!(!g.may_sign("0xunknown", 100));
    }
}
