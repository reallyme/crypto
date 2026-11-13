// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::copy_inputs::{copy_bytes, require_known};
use crate::{RsaPssParams, RsaPublicKeyDerEncoding};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeVerificationResult, CryptoRsaPssVerifyRequest,
    CryptoRsaPublicKeyDerEncodingIdentifier, CryptoVerificationStatus,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns exact PSS verification inputs and independently selected native params.
/// SHA-1 retains only the primitive's existing historical verification scope.
pub struct RsaPssVerifyInputs {
    encoding: RsaPublicKeyDerEncoding,
    params: RsaPssParams,
    public_key_der: Zeroizing<Vec<u8>>,
    message: Zeroizing<Vec<u8>>,
    signature: Zeroizing<Vec<u8>>,
}

impl RsaPssVerifyInputs {
    /// Returns the exact native encoding identity.
    pub fn encoding(&self) -> RsaPublicKeyDerEncoding {
        self.encoding
    }

    /// Preserves independent message hash, MGF1 hash and explicit salt length.
    pub fn params(&self) -> RsaPssParams {
        self.params
    }

    /// Borrows the unmodified caller DER.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Borrows the exact caller message, including empty or non-text bytes.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Borrows the exact caller signature without width normalization.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Verifies through the unchanged primitive and preserves its typed errors.
    /// A mismatch remains an error; only verified inputs produce VALID status.
    pub fn verify(&self) -> Result<CryptoNativeVerificationResult, CryptoError> {
        crate::verify_rsa_pss(
            &self.public_key_der,
            self.encoding,
            self.params,
            &self.message,
            &self.signature,
        )?;
        Ok(CryptoNativeVerificationResult {
            status: CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID.into(),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

impl TryFrom<&CryptoRsaPssVerifyRequest> for RsaPssVerifyInputs {
    type Error = CryptoError;

    fn try_from(value: &CryptoRsaPssVerifyRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let encoding =
            RsaPublicKeyDerEncoding::try_from(&CryptoRsaPublicKeyDerEncodingIdentifier {
                encoding: value.public_key_encoding,
                __buffa_unknown_fields: Default::default(),
            })?;
        let params = RsaPssParams::try_from(
            value
                .params
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        super::admit_inputs::pss(&value.public_key_der, encoding, &value.signature)?;
        Ok(Self {
            encoding,
            params,
            public_key_der: copy_bytes(&value.public_key_der)?,
            message: copy_bytes(&value.message)?,
            signature: copy_bytes(&value.signature)?,
        })
    }
}

impl Zeroize for RsaPssVerifyInputs {
    fn zeroize(&mut self) {
        self.public_key_der.zeroize();
        self.message.zeroize();
        self.signature.zeroize();
    }
}

// The independent clearing fields protect partial construction and every exit.
impl ZeroizeOnDrop for RsaPssVerifyInputs {}
