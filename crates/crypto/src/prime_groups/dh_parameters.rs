// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_bigint::BoxedUint;
use zeroize::Zeroizing;

use super::{field, CryptoError, PrimeGroup};

fn canonical(value: &[u8], maximum: usize) -> Result<(), CryptoError> {
    if value.is_empty() || value.len() > maximum {
        return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
    }
    if value.first() == Some(&0) {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    Ok(())
}

impl PrimeGroup {
    /// Validate minimal unsigned big-endian DH parameters for this built-in group.
    ///
    /// Exact `p` and `g` identify the registered subgroup even when `q` is absent.
    /// A supplied `q` must match; a supplied `j` must equal `(p - 1) / q`, using
    /// the built-in order whether or not `q` was supplied. Present-empty values,
    /// sign padding and elliptic-curve groups are rejected. Protocol strength
    /// and acceptance remain caller policy; no caller-defined group is admitted.
    pub fn validate_dh_parameters(
        self,
        p: &[u8],
        g: &[u8],
        q: Option<&[u8]>,
        j: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        if self.is_elliptic_curve() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        canonical(p, self.field_len())?;
        canonical(g, self.field_len())?;
        if let Some(value) = q {
            canonical(value, self.scalar_len())?;
        }
        if let Some(value) = j {
            canonical(value, self.field_len())?;
        }
        if p != self.modulus()
            || g != self.standard_generator_encoding()
            || q.is_some_and(|value| value != self.order())
        {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        if let Some(j) = j {
            // Arithmetic starts only after exact registry matching. Its widths
            // and divisor are built-in public constants; callers cannot select
            // primality work, preprocessing or an arbitrarily large allocation.
            let bits = field::precision(self.field_len())?;
            let modulus = field::integer(self.modulus(), bits)?;
            let one = Zeroizing::new(BoxedUint::one_with_precision(bits));
            // Every registered modulus is greater than one, so this fixed-width
            // subtraction cannot wrap. No caller-selected value reaches it.
            let pm1 = Zeroizing::new(modulus.wrapping_sub(&one));
            let divisor = field::params(self.order())?;
            let (quotient, remainder) = pm1.div_rem(divisor.modulus().as_nz_ref());
            let quotient = Zeroizing::new(quotient);
            let remainder = Zeroizing::new(remainder);
            let supplied = field::integer(j, bits)?;
            if !bool::from(remainder.is_zero()) || *quotient != *supplied {
                return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
            }
        }
        Ok(())
    }
}
