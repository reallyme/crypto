// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use secrecy::{ExposeSecret, SecretSlice};
use zeroize::ZeroizeOnDrop;

use super::{dh, ec, field, secret, GroupError, GroupErrorReason, PrimeGroup};

/// Canonical, validated, nonidentity subgroup element with an erasing owner.
///
/// ```compile_fail
/// use reallyme_crypto::prime_groups::GroupElement;
/// fn disclose(point: GroupElement) { let _ = format!("{point:?}"); }
/// ```
pub struct GroupElement {
    pub(super) group: PrimeGroup,
    pub(super) bytes: SecretSlice<u8>,
}

impl ZeroizeOnDrop for GroupElement {}

impl PrimeGroup {
    /// Import an exact-width unsigned DH value or uncompressed SEC1 point.
    /// Identity, out-of-field, off-curve and wrong-subgroup values are rejected.
    pub fn element(self, bytes: &[u8]) -> Result<GroupElement, GroupError> {
        if bytes.len() != self.element_len() {
            return Err(GroupErrorReason::InvalidLength.into());
        }
        if self.is_elliptic_curve() {
            ec::validate(self, bytes)?;
        } else {
            dh::validate(self, bytes)?;
        }
        Ok(GroupElement {
            group: self,
            bytes: secret::copy(bytes)?,
        })
    }

    /// Validated standard generator.
    pub fn generator(self) -> Result<GroupElement, GroupError> {
        self.element(self.domain().generator)
    }

    /// Compute `[n] base + offset` for EC, or `base^n * offset` for DH.
    /// The bounded big-endian integer n is reduced modulo the subgroup order;
    /// zero is valid here, while the final identity remains forbidden.
    pub fn linear_combination(
        self,
        n: &[u8],
        base: &GroupElement,
        offset: &GroupElement,
    ) -> Result<GroupElement, GroupError> {
        if base.group != self || offset.group != self {
            return Err(GroupErrorReason::GroupMismatch.into());
        }
        let params = field::params(self.order())?;
        let reduced = field::reduce(n, &params)?;
        let scalar = field::encode(&reduced, self.scalar_len())?;
        let bytes = if self.is_elliptic_curve() {
            ec::combine(
                self,
                base.encoding(),
                scalar.expose_secret(),
                offset.encoding(),
            )?
        } else {
            dh::combine(
                self,
                base.encoding(),
                scalar.expose_secret(),
                offset.encoding(),
            )?
        };
        Ok(GroupElement { group: self, bytes })
    }
}

impl GroupElement {
    /// Domain identity, retained across every group operation.
    #[must_use]
    pub const fn group(&self) -> PrimeGroup {
        self.group
    }

    /// Explicit borrow of the canonical encoding. Intermediate points can be
    /// secret; callers must not log or retain this borrow in unprotected owners.
    #[must_use]
    pub fn encoding(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    /// Key-agreement encoding: fixed-width x for EC, full fixed-width DH value.
    pub fn agreement_secret(&self) -> Result<SecretSlice<u8>, GroupError> {
        let bytes = if self.group.is_elliptic_curve() {
            let end = self
                .group
                .field_len()
                .checked_add(1)
                .ok_or(GroupErrorReason::Arithmetic)?;
            self.encoding()
                .get(1..end)
                .ok_or(GroupErrorReason::Arithmetic)?
        } else {
            self.encoding()
        };
        secret::copy(bytes)
    }
}
