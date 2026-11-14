// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact existing low-S, representation and P-256 container import profiles.

use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoEcdsaPublicKey, CryptoEcdsaPublicKeyValidationRequest,
    CryptoEcdsaSignatureTranscodeRequest, CryptoNativeSignatureResult,
    CryptoNativeVerificationResult, CryptoP256CompressedPublicKeyRequest,
    CryptoP256LowSSignRequest, CryptoP256LowSVerifyRequest,
    CryptoP256PrivateKeyContainerImportRequest, CryptoP256PublicKeyContainerImportRequest,
    P256KeyContainerFormat,
};
use zeroize::Zeroizing;

use super::{EcdsaCurve, EcdsaEncoding, EcdsaInput, EcdsaKey};
use crate::native_contract_support::{copy_bytes, verified};

/// Transcode the seven existing explicit curves, retaining high-S values.
/// Matching representations do not denote an additional normalization policy.
pub fn transcode_signature(
    request: &CryptoEcdsaSignatureTranscodeRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    let curve = EcdsaCurve::try_from(
        request
            .curve
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let source = EcdsaEncoding::try_from(request.source_encoding)?;
    let target = EcdsaEncoding::try_from(request.target_encoding)?;
    let value = Zeroizing::new(match (source, target) {
        (EcdsaEncoding::Der, EcdsaEncoding::FixedWidth) => {
            super::der_to_fixed(curve, &request.signature)?
        }
        (EcdsaEncoding::FixedWidth, EcdsaEncoding::Der) => {
            super::fixed_to_der(curve, &request.signature)?
        }
        _ => return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
    });
    signature(&value)
}

/// Invoke the canonical P-256/SHA-256 profile with an existing non-exporting
/// owner. The compatibility signing APIs and their S policy are unchanged.
pub fn sign_p256_low_s(
    key: &EcdsaKey,
    request: &CryptoP256LowSSignRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    let input = EcdsaInput::try_from(
        request
            .input
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let signature_bytes = Zeroizing::new(key.sign_p256_low_s(input)?);
    signature(&signature_bytes)
}

/// Existing digest-only strict verification rejects high-S twins. It never
/// guesses that a 32-byte original message is an already-computed digest.
pub fn verify_p256_low_s(
    request: &CryptoP256LowSVerifyRequest,
) -> Result<CryptoNativeVerificationResult, CryptoError> {
    let digest = crypto_p256::P256Sha256Digest::try_from_slice(&request.sha256_digest)?;
    #[cfg(any(feature = "native", feature = "wasm"))]
    {
        crypto_p256::verify_p256_sha256_digest_low_s_der(
            &request.signature_der,
            &digest,
            &request.public_key_sec1,
        )?;
        Ok(verified())
    }
    #[cfg(not(any(feature = "native", feature = "wasm")))]
    {
        let _ = digest;
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Standalone full point validation under the selected explicit curve.
pub fn validate_public_key(
    request: &CryptoEcdsaPublicKeyValidationRequest,
) -> Result<CryptoNativeVerificationResult, CryptoError> {
    let curve = EcdsaCurve::try_from(
        request
            .curve
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    super::validate_public_key(curve, &request.public_key_sec1)?;
    Ok(verified())
}

fn container_format(
    value: buffa::EnumValue<P256KeyContainerFormat>,
) -> Result<P256KeyContainerFormat, CryptoError> {
    value
        .as_known()
        .filter(|value| *value != P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_UNSPECIFIED)
        .ok_or(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
}

/// Import an existing P-256 container into the existing private owner. The
/// native parser's private scalar immediately remains in clearing storage.
/// No private scalar appears in a result DTO or newly public accessor.
pub fn import_p256_private(
    request: &CryptoP256PrivateKeyContainerImportRequest,
) -> Result<EcdsaKey, CryptoError> {
    let format = container_format(request.format)?;
    #[cfg(feature = "native")]
    {
        let scalar = match format {
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_DER => {
                crypto_p256::private_key_from_pkcs8_der(&request.document)?
            }
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SEC1_DER => {
                crypto_p256::private_key_from_sec1_der(&request.document)?
            }
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PKCS8_PEM => {
                crypto_p256::private_key_from_pkcs8_pem(pem(&request.document)?)?
            }
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SEC1_PEM => {
                crypto_p256::private_key_from_sec1_pem(pem(&request.document)?)?
            }
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_PRIVATE_PEM => {
                crypto_p256::private_key_from_pem(pem(&request.document)?)?
            }
            _ => return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        };
        EcdsaKey::import(EcdsaCurve::P256, scalar.as_slice())
    }
    #[cfg(not(feature = "native"))]
    {
        let _ = format;
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Preserve the native SPKI import helper's compressed SEC1 output.
pub fn import_p256_public(
    request: &CryptoP256PublicKeyContainerImportRequest,
) -> Result<CryptoEcdsaPublicKey, CryptoError> {
    let format = container_format(request.format)?;
    #[cfg(feature = "native")]
    {
        let public = Zeroizing::new(match format {
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SPKI_DER => {
                crypto_p256::public_key_from_spki_der(&request.document)?
            }
            P256KeyContainerFormat::P256_KEY_CONTAINER_FORMAT_SPKI_PEM => {
                crypto_p256::public_key_from_spki_pem(pem(&request.document)?)?
            }
            _ => return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        });
        crate::format_contract::p256_public(public.as_slice())
    }
    #[cfg(not(feature = "native"))]
    {
        let _ = format;
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Invoke the existing native-only compressed derivation without scalar export.
pub fn compressed_p256_public_key(
    key: &EcdsaKey,
    _: &CryptoP256CompressedPublicKeyRequest,
) -> Result<CryptoEcdsaPublicKey, CryptoError> {
    #[cfg(feature = "native")]
    {
        let public = Zeroizing::new(key.compressed_p256_public_key()?);
        crate::format_contract::p256_public(public.as_slice())
    }
    #[cfg(not(feature = "native"))]
    {
        let _ = key;
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

#[cfg(feature = "native")]
fn pem(document: &[u8]) -> Result<&str, CryptoError> {
    core::str::from_utf8(document).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)
}

fn signature(bytes: &[u8]) -> Result<CryptoNativeSignatureResult, CryptoError> {
    let mut output = CryptoNativeSignatureResult::default();
    copy_bytes(&mut output.signature, bytes)?;
    Ok(output)
}
