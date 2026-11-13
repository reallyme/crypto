// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected comparison inputs retain the native equality and error semantics.

use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoConstantTimeCompareRequest, CryptoConstantTimeCompareResult,
    CryptoConstantTimeRequireEqualResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns comparison inputs without diagnostic or serialization exposure.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ConstantTimeInputs {
    left: Zeroizing<Vec<u8>>,
    right: Zeroizing<Vec<u8>>,
}
impl ConstantTimeInputs {
    /// Unequal lengths remain public metadata and compare false.
    pub fn equal(&self) -> bool {
        crate::ct_eq(&self.left, &self.right)
    }
    /// Returns the native fixed-array comparison after validating both widths.
    pub fn equal_fixed<const N: usize>(&self) -> Result<bool, CryptoError> {
        let left = <&[u8; N]>::try_from(self.left.as_slice())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let right = <&[u8; N]>::try_from(self.right.as_slice())
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        Ok(crate::ct_eq_fixed(left, right))
    }
    /// Preserves invalid-length versus equal-width verification failure.
    pub fn require_equal(&self) -> Result<CryptoConstantTimeRequireEqualResult, CryptoError> {
        crate::require_ct_eq(&self.left, &self.right)?;
        Ok(CryptoConstantTimeRequireEqualResult::default())
    }
    /// Reports comparison only; it is not a caller-supplied verification override.
    pub fn compare_result(&self) -> CryptoConstantTimeCompareResult {
        CryptoConstantTimeCompareResult {
            equal: self.equal(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}
impl TryFrom<&CryptoConstantTimeCompareRequest> for ConstantTimeInputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoConstantTimeCompareRequest) -> Result<Self, Self::Error> {
        if !value.__buffa_unknown_fields.is_empty() {
            return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
        }
        Ok(Self {
            left: copy_bytes(&value.left)?,
            right: copy_bytes(&value.right)?,
        })
    }
}
fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    u32::try_from(bytes.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.extend_from_slice(bytes);
    Ok(output)
}
