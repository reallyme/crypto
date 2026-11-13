// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::copy_inputs::{copy_bytes, copy_into, require_known};
use crate::{RsaPublicKeyDerEncoding, RsaPublicRepresentatives};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRsaPublicKeyDerEncodingIdentifier, CryptoRsaPublicRepresentativesRequest,
    CryptoRsaPublicRepresentativesResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns exact DER and signature bytes for the existing bounded public operation.
/// Neither representative establishes signature validity or trust.
pub struct PublicRepresentativesInputs {
    encoding: RsaPublicKeyDerEncoding,
    public_key_der: Zeroizing<Vec<u8>>,
    signature: Zeroizing<Vec<u8>>,
}

impl PublicRepresentativesInputs {
    /// Returns the native DER wrapper identity without guessing from the bytes.
    pub fn encoding(&self) -> RsaPublicKeyDerEncoding {
        self.encoding
    }

    /// Borrows the unmodified caller-supplied DER.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Borrows the exact-width signature representation without trimming zeros.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the existing protected native representative owner.
    pub fn recover(&self) -> Result<RsaPublicRepresentatives, CryptoError> {
        crate::rsa_public_representatives(&self.public_key_der, self.encoding, &self.signature)
    }

    /// Copies both exact-width representatives through a final clearing DTO.
    pub fn result(&self) -> Result<CryptoRsaPublicRepresentativesResult, CryptoError> {
        let native = self.recover()?;
        CryptoRsaPublicRepresentativesResult::try_from(&native)
    }
}

impl TryFrom<&CryptoRsaPublicRepresentativesRequest> for PublicRepresentativesInputs {
    type Error = CryptoError;

    fn try_from(value: &CryptoRsaPublicRepresentativesRequest) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let encoding =
            RsaPublicKeyDerEncoding::try_from(&CryptoRsaPublicKeyDerEncodingIdentifier {
                encoding: value.public_key_encoding,
                __buffa_unknown_fields: Default::default(),
            })?;
        super::admit_inputs::representatives(&value.public_key_der, encoding, &value.signature)?;
        Ok(Self {
            encoding,
            public_key_der: copy_bytes(&value.public_key_der)?,
            signature: copy_bytes(&value.signature)?,
        })
    }
}

impl Zeroize for PublicRepresentativesInputs {
    fn zeroize(&mut self) {
        self.public_key_der.zeroize();
        self.signature.zeroize();
    }
}

// Each copied field is a clearing owner, including on partial construction.
impl ZeroizeOnDrop for PublicRepresentativesInputs {}

impl TryFrom<&RsaPublicRepresentatives> for CryptoRsaPublicRepresentativesResult {
    type Error = CryptoError;

    fn try_from(value: &RsaPublicRepresentatives) -> Result<Self, Self::Error> {
        let mut output = Self::default();
        copy_into(&mut output.ordinary, value.ordinary())?;
        copy_into(&mut output.complement, value.complement())?;
        Ok(output)
    }
}
