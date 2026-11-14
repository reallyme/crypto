// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Borrowed message/prehash conversion and protected native ECDSA adapters.
//! These standalone contracts do not register executable wire operations.

use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_ecdsa_input::Input, CryptoEcdsaAgreementRequest,
    CryptoEcdsaCurveIdentifier, CryptoEcdsaInput, CryptoEcdsaKeyDescriptor,
    CryptoEcdsaKeyGenerateRequest, CryptoEcdsaKeyImportRequest, CryptoEcdsaPublicKey,
    CryptoEcdsaSignOptions, CryptoEcdsaSignRequest, CryptoEcdsaVerifyRequest,
    CryptoNativeAgreementResult, CryptoNativePublicKeyRequest, CryptoNativeSignatureResult,
    CryptoNativeVerificationResult, EcdsaCurve as ProtoCurve, NativeKeySource,
};
use secrecy::{ExposeSecret, SecretSlice};
use zeroize::Zeroizing;

use super::{EcdsaCurve, EcdsaEncoding, EcdsaHash, EcdsaInput, EcdsaKey, OpaqueEcdsaSigner};
use crate::native_contract_support::{capabilities, copy_bytes, verified};

impl<'a> TryFrom<&'a CryptoEcdsaInput> for EcdsaInput<'a> {
    type Error = CryptoError;
    fn try_from(value: &'a CryptoEcdsaInput) -> Result<Self, Self::Error> {
        match value
            .input
            .as_ref()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?
        {
            Input::Message(input) => Ok(Self::Message {
                hash: EcdsaHash::try_from(input.hash)?,
                bytes: &input.message,
            }),
            Input::Prehash(input) => {
                let hash = EcdsaHash::try_from(input.hash)?;
                let length = match hash {
                    EcdsaHash::Sha256 => crypto_sha2_256::SHA2_256_DIGEST_LENGTH,
                    EcdsaHash::Sha384 => crypto_sha2::SHA2_384_DIGEST_LENGTH,
                    EcdsaHash::Sha512 => crypto_sha2::SHA2_512_DIGEST_LENGTH,
                };
                if input.digest.len() != length {
                    return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
                }
                Ok(Self::Prehash {
                    hash,
                    bytes: &input.digest,
                })
            }
        }
    }
}

impl TryFrom<&CryptoEcdsaKeyImportRequest> for EcdsaKey {
    type Error = CryptoError;
    fn try_from(value: &CryptoEcdsaKeyImportRequest) -> Result<Self, Self::Error> {
        let curve = EcdsaCurve::try_from(
            value
                .curve
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        Self::import(curve, &value.scalar)
    }
}

fn options(value: &CryptoEcdsaSignOptions) -> Result<EcdsaEncoding, CryptoError> {
    EcdsaEncoding::try_from(value.encoding)
}
fn identifier(curve: EcdsaCurve) -> CryptoEcdsaCurveIdentifier {
    CryptoEcdsaCurveIdentifier {
        curve: ProtoCurve::from(curve).into(),
    }
}
fn public_output(curve: EcdsaCurve, bytes: &[u8]) -> Result<CryptoEcdsaPublicKey, CryptoError> {
    let mut output = CryptoEcdsaPublicKey {
        curve: MessageField::some(identifier(curve)),
        sec1: Vec::new().into(),
    };
    copy_bytes(&mut output.sec1, bytes)?;
    Ok(output)
}

/// Generate a native non-exporting owner; only its public descriptor is serializable.
pub fn generate(request: &CryptoEcdsaKeyGenerateRequest) -> Result<EcdsaKey, CryptoError> {
    EcdsaKey::generate(EcdsaCurve::try_from(
        request
            .curve
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?)
}
/// Generate with the existing injected cryptographic entropy boundary.
pub fn generate_with_rng(
    request: &CryptoEcdsaKeyGenerateRequest,
    rng: &mut impl crate::key_random::KeyRng,
) -> Result<EcdsaKey, CryptoError> {
    EcdsaKey::generate_with_rng(
        EcdsaCurve::try_from(
            request
                .curve
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?,
        rng,
    )
}
/// Borrow public bytes from the explicitly supplied owner without private export.
pub fn public_key(
    key: &EcdsaKey,
    _: &CryptoNativePublicKeyRequest,
) -> Result<CryptoEcdsaPublicKey, CryptoError> {
    public_output(key.curve(), key.public_key())
}
/// Describe signing/agreement method support and private owner cleanup.
/// Native operations still validate the key, including after explicit zeroization.
pub fn describe_software(key: &EcdsaKey) -> Result<CryptoEcdsaKeyDescriptor, CryptoError> {
    super::validate_public_key(key.curve(), key.public_key())?;
    Ok(CryptoEcdsaKeyDescriptor {
        public_key: MessageField::some(public_output(key.curve(), key.public_key())?),
        capabilities: MessageField::some(capabilities(
            NativeKeySource::NATIVE_KEY_SOURCE_SOFTWARE_OWNER,
            true,
            true,
            false,
            true,
        )?),
    })
}
/// Describe only the injected trait's signing/public-key capabilities.
pub fn describe_opaque(
    provider: &impl OpaqueEcdsaSigner,
) -> Result<CryptoEcdsaKeyDescriptor, CryptoError> {
    // Snapshot the provider's reported association once, matching the native
    // signing boundary rather than mixing repeated capability getter calls.
    let curve = provider.curve();
    let public = provider.public_key();
    super::validate_public_key(curve, public)?;
    Ok(CryptoEcdsaKeyDescriptor {
        public_key: MessageField::some(public_output(curve, public)?),
        capabilities: MessageField::some(capabilities(
            NativeKeySource::NATIVE_KEY_SOURCE_OPAQUE_SIGNER,
            true,
            false,
            false,
            false,
        )?),
    })
}
/// Sign exact input with a borrowed protected software owner.
pub fn sign(
    key: &EcdsaKey,
    request: &CryptoEcdsaSignRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    let input = EcdsaInput::try_from(
        request
            .input
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let encoding = options(
        request
            .options
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let signature = Zeroizing::new(key.sign(input, encoding)?);
    let mut output = CryptoNativeSignatureResult::default();
    copy_bytes(&mut output.signature, &signature)?;
    Ok(output)
}
/// Sign through the native provider path, which verifies exact bytes/key association.
pub fn sign_opaque(
    provider: &impl OpaqueEcdsaSigner,
    request: &CryptoEcdsaSignRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    let input = EcdsaInput::try_from(
        request
            .input
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let encoding = options(
        request
            .options
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let signature = Zeroizing::new(super::sign_with_provider(provider, input, encoding)?);
    let mut output = CryptoNativeSignatureResult::default();
    copy_bytes(&mut output.signature, &signature)?;
    Ok(output)
}
/// Verify without guessing a hash, representation or message/prehash boundary.
pub fn verify(
    request: &CryptoEcdsaVerifyRequest,
) -> Result<CryptoNativeVerificationResult, CryptoError> {
    let public = request
        .public_key
        .as_option()
        .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    let curve = EcdsaCurve::try_from(
        public
            .curve
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let input = EcdsaInput::try_from(
        request
            .input
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    let encoding = options(
        request
            .options
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    super::verify(curve, &public.sec1, input, &request.signature, encoding)?;
    Ok(verified())
}
/// Return the unchanged native clearing agreement owner.
pub fn agree(
    key: &EcdsaKey,
    request: &CryptoEcdsaAgreementRequest,
) -> Result<SecretSlice<u8>, CryptoError> {
    key.agree(&request.peer_sec1)
}
/// Explicit protected copy for transports that require the native shared secret.
pub fn agreement_result(
    secret: &SecretSlice<u8>,
) -> Result<CryptoNativeAgreementResult, CryptoError> {
    let mut output = CryptoNativeAgreementResult::default();
    copy_bytes(&mut output.shared_secret, secret.expose_secret())?;
    Ok(output)
}
