// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use zeroize::ZeroizeOnDrop;

use crate::key_random::KeyRng;

use super::{dh, ec, field, secret, CryptoError, GroupElement, PrimeGroup};

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
    pub fn scalar(self, bytes: &[u8]) -> Result<GroupScalar, CryptoError> {
        if bytes.len() != self.scalar_len() {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        let order = field::params(self.order())?;
        let value = field::integer(bytes, order.bits_precision())?;
        if bool::from(value.is_zero()) || *value >= **order.modulus() {
            return Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY);
        }
        Ok(GroupScalar {
            group: self,
            bytes: secret::copy(bytes)?,
        })
    }

    /// Uniform bounded rejection sampling with an injected cryptographic RNG.
    pub fn random_scalar(self, rng: &mut impl KeyRng) -> Result<GroupScalar, CryptoError> {
        let mut candidate = secret::zeros(self.scalar_len())?;
        let leading = self
            .order()
            .first()
            .ok_or(CryptoError::BACKEND_INTERNAL)?
            .leading_zeros();
        let mask = u8::MAX
            .checked_shr(leading)
            .ok_or(CryptoError::BACKEND_INTERNAL)?;
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            rng.fill(candidate.expose_secret_mut())?;
            let first = candidate
                .expose_secret_mut()
                .first_mut()
                .ok_or(CryptoError::BACKEND_INTERNAL)?;
            *first &= mask;
            match self.scalar(candidate.expose_secret()) {
                Ok(scalar) => return Ok(scalar),
                Err(error) if error == CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY => (),
                Err(error) => return Err(error),
            }
        }
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
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
    pub fn multiply(&self, base: &GroupElement) -> Result<GroupElement, CryptoError> {
        if self.group != base.group {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
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
    pub fn public_element(&self) -> Result<GroupElement, CryptoError> {
        self.multiply(&self.group.generator()?)
    }
}
