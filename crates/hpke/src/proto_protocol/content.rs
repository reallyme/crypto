// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Call content borrows a separately owned live context; no state can be imported.

use super::requests::{check_length, copy_bytes, copy_into, require_known};
use crate::{HpkeError, HpkeOpenOutput, HpkeReceiverContext, HpkeSenderContext};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHpkeReceiverOpenRequest, CryptoHpkeReceiverOpenResult, CryptoHpkeSenderSealRequest,
    CryptoHpkeSenderSealResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Native request borrowing exactly one mutable sender owner.
pub struct HpkeSenderSealRequest<'a> {
    /// Single-owner traffic state; the call advances its sequence internally.
    pub context: &'a mut HpkeSenderContext,
    /// Exact caller-supplied authenticated data.
    pub aad: &'a [u8],
    /// Borrowed plaintext retained by the caller.
    pub plaintext: &'a [u8],
}
impl HpkeSenderSealRequest<'_> {
    /// Seals through the existing native context without selecting another provider.
    pub fn seal(self) -> Result<Vec<u8>, HpkeError> {
        self.context.seal(self.aad, self.plaintext)
    }
}
/// Native request borrowing exactly one mutable receiver owner.
pub struct HpkeReceiverOpenRequest<'a> {
    /// Single-owner traffic state; the call advances its sequence internally.
    pub context: &'a mut HpkeReceiverContext,
    /// Exact caller-supplied authenticated data.
    pub aad: &'a [u8],
    /// Borrowed ciphertext authenticated by the native owner.
    pub ciphertext: &'a [u8],
}
impl HpkeReceiverOpenRequest<'_> {
    /// Returns the existing protected plaintext owner only after authentication.
    pub fn open(self) -> Result<HpkeOpenOutput, HpkeError> {
        self.context.open(self.aad, self.ciphertext)
    }
}

/// Protected per-record sender content without any context identifier or state.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeSenderSealInputs {
    aad: Zeroizing<Vec<u8>>,
    plaintext: Zeroizing<Vec<u8>>,
}
impl HpkeSenderSealInputs {
    /// Borrows the content and an explicitly supplied native context together.
    pub fn as_request<'a>(
        &'a self,
        context: &'a mut HpkeSenderContext,
    ) -> HpkeSenderSealRequest<'a> {
        HpkeSenderSealRequest {
            context,
            aad: &self.aad,
            plaintext: &self.plaintext,
        }
    }
}
impl TryFrom<&CryptoHpkeSenderSealRequest> for HpkeSenderSealInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeSenderSealRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        Ok(Self {
            aad: copy_bytes(&value.aad)?,
            plaintext: copy_bytes(&value.plaintext)?,
        })
    }
}
/// Copies a public ciphertext result without exposing any sender state.
pub fn sender_seal_public_result(value: &[u8]) -> Result<CryptoHpkeSenderSealResult, HpkeError> {
    check_length(value)?;
    let mut output = CryptoHpkeSenderSealResult::default();
    copy_into(&mut output.ciphertext, value)?;
    Ok(output)
}
/// Protected per-record receiver content; it cannot reconstruct a context.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HpkeReceiverOpenInputs {
    aad: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
}
impl HpkeReceiverOpenInputs {
    /// Borrows the content and an explicitly supplied native receiver together.
    pub fn as_request<'a>(
        &'a self,
        context: &'a mut HpkeReceiverContext,
    ) -> HpkeReceiverOpenRequest<'a> {
        HpkeReceiverOpenRequest {
            context,
            aad: &self.aad,
            ciphertext: &self.ciphertext,
        }
    }
}
impl TryFrom<&CryptoHpkeReceiverOpenRequest> for HpkeReceiverOpenInputs {
    type Error = HpkeError;
    fn try_from(value: &CryptoHpkeReceiverOpenRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        Ok(Self {
            aad: copy_bytes(&value.aad)?,
            ciphertext: copy_bytes(&value.ciphertext)?,
        })
    }
}
impl TryFrom<&HpkeOpenOutput> for CryptoHpkeReceiverOpenResult {
    type Error = HpkeError;
    fn try_from(value: &HpkeOpenOutput) -> Result<Self, Self::Error> {
        check_length(&value.plaintext)?;
        let mut output = Self::default();
        copy_into(&mut output.plaintext, &value.plaintext)?;
        Ok(output)
    }
}

impl TryFrom<&HpkeSenderSealRequest<'_>> for CryptoHpkeSenderSealRequest {
    type Error = HpkeError;
    // Only content is copied; the borrowed native context remains opaque.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkeSenderSealRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.aad)?;
        check_length(value.plaintext)?;
        let mut output = Self::default();
        copy_into(&mut output.aad, value.aad)?;
        copy_into(&mut output.plaintext, value.plaintext)?;
        Ok(output)
    }
}
impl TryFrom<&HpkeReceiverOpenRequest<'_>> for CryptoHpkeReceiverOpenRequest {
    type Error = HpkeError;
    // Only content is copied; no context identifier or state crosses this boundary.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &HpkeReceiverOpenRequest<'_>) -> Result<Self, Self::Error> {
        check_length(value.aad)?;
        check_length(value.ciphertext)?;
        let mut output = Self::default();
        copy_into(&mut output.aad, value.aad)?;
        copy_into(&mut output.ciphertext, value.ciphertext)?;
        Ok(output)
    }
}
