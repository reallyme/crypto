// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::parameters;

/// Reviewed standard prime-order groups. Protocol strength policy is external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimeGroup {
    /// RFC 5114 section 2.1. Legacy 1024-bit modulus, 160-bit subgroup.
    Rfc5114Dh1024_160,
    /// RFC 5114 section 2.2. 2048-bit modulus, 224-bit subgroup.
    Rfc5114Dh2048_224,
    /// RFC 5114 section 2.3. 2048-bit modulus, 256-bit subgroup.
    Rfc5114Dh2048_256,
    /// NIST P-256.
    NistP256,
    /// brainpoolP256r1.
    BrainpoolP256r1,
    /// brainpoolP320r1.
    BrainpoolP320r1,
    /// NIST P-384.
    NistP384,
    /// brainpoolP384r1.
    BrainpoolP384r1,
    /// brainpoolP512r1.
    BrainpoolP512r1,
    /// NIST P-521.
    NistP521,
}

pub(super) struct Domain {
    pub p: &'static [u8],
    pub q: &'static [u8],
    pub generator: &'static [u8],
    pub a: &'static [u8],
    pub b: &'static [u8],
}

impl PrimeGroup {
    pub(super) fn domain(self) -> Domain {
        parameters::domain(self)
    }

    /// Canonical field element width, including P-521 leading padding bits.
    #[must_use]
    pub fn field_len(self) -> usize {
        self.domain().p.len()
    }

    /// Canonical scalar width.
    #[must_use]
    pub fn scalar_len(self) -> usize {
        self.domain().q.len()
    }

    /// Fixed-width DH value or uncompressed SEC1 point width.
    #[must_use]
    pub fn element_len(self) -> usize {
        self.domain().generator.len()
    }

    /// Public prime modulus, as a minimal unsigned big-endian integer.
    #[must_use]
    pub fn modulus(self) -> &'static [u8] {
        self.domain().p
    }

    /// Public prime subgroup order, as a minimal unsigned big-endian integer.
    #[must_use]
    pub fn order(self) -> &'static [u8] {
        self.domain().q
    }

    /// Public coefficients (a, b) for y² = x³ + ax + b. DH has no curve.
    #[must_use]
    pub fn curve_coefficients(self) -> Option<(&'static [u8], &'static [u8])> {
        let domain = self.domain();
        if self.is_elliptic_curve() {
            Some((domain.a, domain.b))
        } else {
            None
        }
    }

    /// Public standard generator encoding, never a computed secret element.
    #[must_use]
    pub fn standard_generator_encoding(self) -> &'static [u8] {
        self.domain().generator
    }

    /// Whether elements use uncompressed SEC1 encoding.
    #[must_use]
    pub const fn is_elliptic_curve(self) -> bool {
        !matches!(
            self,
            Self::Rfc5114Dh1024_160 | Self::Rfc5114Dh2048_224 | Self::Rfc5114Dh2048_256
        )
    }
}
