// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Stable, secret-free group failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GroupErrorReason {
    /// The bounded encoding has the wrong size.
    #[error("invalid group encoding length")]
    InvalidLength,
    /// Private scalars must be in the interval 1..q.
    #[error("invalid group scalar")]
    InvalidScalar,
    /// The encoding is not a canonical nonidentity subgroup element.
    #[error("invalid group element")]
    InvalidElement,
    /// A result is the identity and cannot be used as a base or shared value.
    #[error("identity group element")]
    Identity,
    /// Operands belong to different domains.
    #[error("group mismatch")]
    GroupMismatch,
    /// The selected field cannot support this encoding operation.
    #[error("unsupported field encoding")]
    UnsupportedMapping,
    /// Field encoding inputs must be canonical and nonzero.
    #[error("invalid field element")]
    InvalidFieldElement,
    /// Secure entropy failed.
    #[error("group randomness unavailable")]
    RandomUnavailable,
    /// The bounded rejection sampler could not produce a valid scalar.
    #[error("group randomness exhausted")]
    RandomExhausted,
    /// Protected output storage could not be reserved.
    #[error("group allocation failed")]
    Allocation,
    /// A checked public size or built-in domain invariant failed.
    #[error("group arithmetic invariant failed")]
    Arithmetic,
}

/// Domain error without provider text or secret input values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{reason}")]
pub struct GroupError {
    reason: GroupErrorReason,
}

impl GroupError {
    /// Stable reason suitable for deterministic FFI mapping.
    #[must_use]
    pub const fn reason(self) -> GroupErrorReason {
        self.reason
    }
}

impl From<GroupErrorReason> for GroupError {
    fn from(reason: GroupErrorReason) -> Self {
        Self { reason }
    }
}
