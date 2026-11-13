// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeSignatureResult, CryptoP256SignatureNormalizeRequest,
    CryptoSecp256k1SignatureTranscodeRequest, EcdsaEncoding,
};
#[cfg(any(feature = "p256", feature = "ecdsa-explicit", feature = "secp256k1"))]
use zeroize::Zeroizing;

use crate::native_contract_support::known_fields;

fn encoding(value: EnumValue<EcdsaEncoding>) -> Result<EcdsaEncoding, CryptoError> {
    match value.as_known() {
        Some(
            value @ (EcdsaEncoding::ECDSA_ENCODING_DER | EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH),
        ) => Ok(value),
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

/// Validate and normalize P-256 S without authenticating any message.
/// The output uses exactly the requested input representation.
pub fn normalize_p256_signature(
    request: &CryptoP256SignatureNormalizeRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let representation = encoding(request.encoding)?;
    #[cfg(any(feature = "p256", feature = "ecdsa-explicit"))]
    {
        match representation {
            EcdsaEncoding::ECDSA_ENCODING_DER => {
                let value = Zeroizing::new(crypto_p256::normalize_p256_ecdsa_der_low_s(
                    &request.signature,
                )?);
                super::signature(&value)
            }
            EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH => {
                let value = Zeroizing::new(crypto_p256::normalize_p256_ecdsa_jose_signature_low_s(
                    &request.signature,
                )?);
                super::signature(value.as_slice())
            }
            EcdsaEncoding::ECDSA_ENCODING_UNSPECIFIED => {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
    }
    #[cfg(not(any(feature = "p256", feature = "ecdsa-explicit")))]
    {
        let _ = representation;
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Convert strict DER and fixed-width secp256k1 signatures without changing S.
/// Matching source/target encodings are rejected rather than treated as a copy.
pub fn transcode_secp256k1_signature(
    request: &CryptoSecp256k1SignatureTranscodeRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let source = encoding(request.source_encoding)?;
    let target = encoding(request.target_encoding)?;
    if source == target {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    #[cfg(feature = "secp256k1")]
    {
        match (source, target) {
            (EcdsaEncoding::ECDSA_ENCODING_DER, EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH) => {
                let value = Zeroizing::new(
                    crypto_secp256k1::secp256k1_ecdsa_der_to_jose_signature(&request.signature)?,
                );
                super::signature(value.as_slice())
            }
            (EcdsaEncoding::ECDSA_ENCODING_FIXED_WIDTH, EcdsaEncoding::ECDSA_ENCODING_DER) => {
                let value = Zeroizing::new(
                    crypto_secp256k1::secp256k1_ecdsa_jose_signature_to_der(&request.signature)?,
                );
                super::signature(&value)
            }
            _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
        }
    }
    #[cfg(not(feature = "secp256k1"))]
    {
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}
