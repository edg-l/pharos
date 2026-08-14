//! Consensus-layer primitive newtypes: `Slot`, `Epoch`, `ValidatorIndex`,
//! `CommitteeIndex`, and `Gwei`.

use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};

macro_rules! define_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
        pub struct $name(pub u64);

        impl $name {
            /// Returns the inner `u64` value.
            pub fn as_u64(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            fn from(v: u64) -> Self {
                Self(v)
            }
        }

        impl From<$name> for u64 {
            fn from(v: $name) -> u64 {
                v.0
            }
        }

        impl Add for $name {
            type Output = Self;
            fn add(self, rhs: Self) -> Self {
                Self(self.0 + rhs.0)
            }
        }

        impl Sub for $name {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                Self(self.0 - rhs.0)
            }
        }

        impl AddAssign for $name {
            fn add_assign(&mut self, rhs: Self) {
                self.0 += rhs.0;
            }
        }

        impl SubAssign for $name {
            fn sub_assign(&mut self, rhs: Self) {
                self.0 -= rhs.0;
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_newtype!(Slot, "A beacon chain slot number.");
define_newtype!(Epoch, "A beacon chain epoch number.");
define_newtype!(ValidatorIndex, "Index into the validator registry.");
define_newtype!(CommitteeIndex, "Index of a committee within a slot.");
define_newtype!(Gwei, "An amount denominated in Gwei (1e-9 ETH).");

impl Slot {
    /// Returns the epoch this slot belongs to, given `slots_per_epoch`.
    pub fn epoch(self, slots_per_epoch: u64) -> Epoch {
        Epoch(self.0 / slots_per_epoch)
    }
}

impl Epoch {
    /// Returns the first slot of this epoch, given `slots_per_epoch`.
    pub fn start_slot(self, slots_per_epoch: u64) -> Slot {
        Slot(self.0 * slots_per_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_epoch_conversion() {
        let slot = Slot(64);
        assert_eq!(slot.epoch(32), Epoch(2));
    }

    #[test]
    fn epoch_start_slot() {
        let epoch = Epoch(3);
        assert_eq!(epoch.start_slot(32), Slot(96));
    }

    #[test]
    fn newtype_arithmetic() {
        let a = Slot(10);
        let b = Slot(5);
        assert_eq!(a + b, Slot(15));
        assert_eq!(a - b, Slot(5));

        let mut c = Slot(10);
        c += Slot(5);
        assert_eq!(c, Slot(15));
        c -= Slot(3);
        assert_eq!(c, Slot(12));
    }

    #[test]
    fn newtype_ordering() {
        assert!(Slot(1) < Slot(2));
        assert!(Epoch(5) > Epoch(3));
        assert_eq!(Gwei(100), Gwei(100));
    }

    #[test]
    fn newtype_display() {
        assert_eq!(Slot(42).to_string(), "42");
        assert_eq!(Epoch(7).to_string(), "7");
    }

    #[test]
    fn from_u64_conversion() {
        let v: Slot = 99u64.into();
        assert_eq!(v.as_u64(), 99);
        let raw: u64 = v.into();
        assert_eq!(raw, 99);
    }

    #[test]
    fn default_is_zero() {
        assert_eq!(Slot::default(), Slot(0));
        assert_eq!(Epoch::default(), Epoch(0));
        assert_eq!(Gwei::default(), Gwei(0));
    }
}
