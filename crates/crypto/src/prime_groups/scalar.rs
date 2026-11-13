// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use zeroize::ZeroizeOnDrop;

use crate::key_random::KeyRng;

use super::{dh, ec, field, secret, GroupElement, GroupError, GroupErrorReason, PrimeGroup};

const MAX_RANDOM_ATTEMPTS: usize = 128;

/// Protected nonzero private scalar, bound to one standard subgroup.
///
/// ```compile_fail
/// use reallyme_crypto::prime_groups::GroupScalar;
/// fn fork(key: GroupScalar) { let _ = key.clone(); }
/// ```
/// ```compile_fail
/// use reallyme_crypto::prime_groups::GroupScalar;
/// fn disclose(key: GroupScalar) { let _ = format!("{key:?}"); }
/// ```
pub struct GroupScalar {
    pub(super) group: PrimeGroup,
    pub(super) bytes: SecretSlice<u8>,
}

impl ZeroizeOnDrop for GroupScalar {}

impl PrimeGroup {
    /// Import a canonical fixed-width scalar in 1..q. No modular reduction of
    /// private-key input is performed, so biased encodings cannot be accepted.
    pub fn scalar(self, bytes: &[u8]) -> Result<GroupScalar, GroupError> {
        if bytes.len() != self.scalar_len() {
            return Err(GroupErrorReason::InvalidLength.into());
        }
        let order = field::params(self.order())?;
        let value = field::integer(bytes, order.bits_precision())?;
        if bool::from(value.is_zero()) || *value >= **order.modulus() {
            return Err(GroupErrorReason::InvalidScalar.into());
        }
        Ok(GroupScalar {
            group: self,
            bytes: secret::copy(bytes)?,
        })
    }

    /// Uniform bounded rejection sampling with an injected cryptographic RNG.
    pub fn random_scalar(self, rng: &mut impl KeyRng) -> Result<GroupScalar, GroupError> {
        let mut candidate = secret::zeros(self.scalar_len())?;
        let leading = self
            .order()
            .first()
            .ok_or(GroupErrorReason::Arithmetic)?
            .leading_zeros();
        let mask = u8::MAX
            .checked_shr(leading)
            .ok_or(GroupErrorReason::Arithmetic)?;
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            rng.fill(candidate.expose_secret_mut())
                .map_err(|_| GroupErrorReason::RandomUnavailable)?;
            let first = candidate
                .expose_secret_mut()
                .first_mut()
                .ok_or(GroupErrorReason::Arithmetic)?;
            *first &= mask;
            match self.scalar(candidate.expose_secret()) {
                Ok(scalar) => return Ok(scalar),
                Err(error) if error.reason() == GroupErrorReason::InvalidScalar => (),
                Err(error) => return Err(error),
            }
        }
        Err(GroupErrorReason::RandomExhausted.into())
    }
}

impl GroupScalar {
    /// The subgroup identity of this private owner.
    #[must_use]
    pub const fn group(&self) -> PrimeGroup {
        self.group
    }

    /// Supplied-base scalar multiplication, returning the complete point/value.
    /// Base validation and subgroup membership cannot be bypassed by callers.
    pub fn multiply(&self, base: &GroupElement) -> Result<GroupElement, GroupError> {
        if self.group != base.group {
            return Err(GroupErrorReason::GroupMismatch.into());
        }
        let bytes = if self.group.is_elliptic_curve() {
            ec::multiply(self.group, base.encoding(), self.bytes.expose_secret())?
        } else {
            dh::multiply(self.group, base.encoding(), self.bytes.expose_secret())?
        };
        Ok(GroupElement {
            group: self.group,
            bytes,
        })
    }

    /// The public key for this scalar and the standard generator.
    pub fn public_element(&self) -> Result<GroupElement, GroupError> {
        self.multiply(&self.group.generator()?)
    }
}
