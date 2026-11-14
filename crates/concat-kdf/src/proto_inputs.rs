// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The existing Concat KDF schema also binds any admitted native output width.
//! Root execution retains its deliberately smaller fixed-width dispatch table.

use crate::{
    JwaAlgorithmId, JwaConcatKdfOutput, JwaConcatKdfRequest, JwaPartyInfo, JwaSharedSecret,
};
use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoJwaConcatKdfSha256DeriveRequest, CryptoJwaConcatKdfSha256DeriveResult, KdfAlgorithm,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected native inputs whose requested output length must equal N exactly.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ConcatKdfInputs<const N: usize> {
    shared_secret: JwaSharedSecret,
    algorithm_id: JwaAlgorithmId,
    party_u_info: JwaPartyInfo,
    party_v_info: JwaPartyInfo,
}
impl<const N: usize> TryFrom<&CryptoJwaConcatKdfSha256DeriveRequest> for ConcatKdfInputs<N> {
    type Error = CryptoError;
    fn try_from(request: &CryptoJwaConcatKdfSha256DeriveRequest) -> Result<Self, Self::Error> {
        let algorithm = request
            .algorithm
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
        match algorithm.algorithm.as_ref() {
            Some(Algorithm::Kdf(value))
                if value.as_known() == Some(KdfAlgorithm::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256) => {}
            _ => return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
        }
        let length = usize::try_from(request.output_length)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        if N < crypto_core::contract_constants::concat_kdf::JWA_CONCAT_KDF_MIN_OUTPUT_LENGTH
            || length != N
        {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        // The native OtherInfo encodes the requested bit length in uint32.
        // Validate that same arithmetic before allocating copied input owners.
        let bits_per_octet =
            usize::try_from(u8::BITS).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        N.checked_mul(bits_per_octet)
            .and_then(|bits| u32::try_from(bits).ok())
            .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        Ok(Self {
            shared_secret: JwaSharedSecret::from_slice(&request.shared_secret)?,
            algorithm_id: JwaAlgorithmId::from_slice(&request.algorithm_id)?,
            party_u_info: JwaPartyInfo::from_slice(&request.party_u_info)?,
            party_v_info: JwaPartyInfo::from_slice(&request.party_v_info)?,
        })
    }
}
impl<const N: usize> ConcatKdfInputs<N> {
    /// Borrow the native request with exact original AlgorithmID and party bytes.
    pub fn as_request(&self) -> JwaConcatKdfRequest<'_> {
        JwaConcatKdfRequest {
            shared_secret: &self.shared_secret,
            algorithm_id: &self.algorithm_id,
            party_u_info: &self.party_u_info,
            party_v_info: &self.party_v_info,
        }
    }
    /// Invoke the unchanged leaf for N, including widths outside root dispatch.
    pub fn derive(&self) -> Result<JwaConcatKdfOutput<N>, CryptoError> {
        crate::derive_jwa_concat_kdf_sha256::<N>(&self.as_request())
    }
    /// Derive through the unchanged native owner and copy into a clearing result.
    pub fn derive_result(&self) -> Result<CryptoJwaConcatKdfSha256DeriveResult, CryptoError> {
        let output = self.derive()?;
        let mut result = CryptoJwaConcatKdfSha256DeriveResult {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(Algorithm::Kdf(
                    KdfAlgorithm::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256.into(),
                )),
            }),
            derived_key: Default::default(),
        };
        result
            .derived_key
            .try_reserve_exact(N)
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        result.derived_key.resize(N, 0)?;
        result.derived_key.copy_from_slice(output.as_bytes());
        Ok(result)
    }
}
