// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ordinary empty-context Ed448 contracts with explicit native key ownership.

use buffa::{EnumValue, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoEd448KeyDescriptor, CryptoEd448KeyImportRequest, CryptoEd448OrdinarySignRequest,
    CryptoEd448OrdinaryVerifyRequest, CryptoEd448PublicKey, CryptoEd448SupportRequest,
    CryptoNativeKeyGenerateRequest, CryptoNativePublicKeyRequest, CryptoNativeSignatureResult,
    CryptoNativeVerificationResult, Ed448Operation as ProtoOperation, NativeKeySource,
};
use zeroize::Zeroizing;

use super::{Ed448Key, Ed448Operation, OpaqueEd448Signer};
use crate::native_contract_support::{capabilities, copy_bytes, known_fields, verified};

impl TryFrom<EnumValue<ProtoOperation>> for Ed448Operation {
    type Error = CryptoError;
    fn try_from(value: EnumValue<ProtoOperation>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoOperation::ED448_OPERATION_VERIFY) => Ok(Self::Verify),
            Some(ProtoOperation::ED448_OPERATION_OPAQUE_SIGN) => Ok(Self::OpaqueSign),
            Some(ProtoOperation::ED448_OPERATION_SOFTWARE_KEY_GENERATION) => {
                Ok(Self::SoftwareKeyGeneration)
            }
            Some(ProtoOperation::ED448_OPERATION_SOFTWARE_KEY_IMPORT) => {
                Ok(Self::SoftwareKeyImport)
            }
            Some(ProtoOperation::ED448_OPERATION_UNSPECIFIED) | None => {
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
        }
    }
}
impl From<Ed448Operation> for ProtoOperation {
    fn from(value: Ed448Operation) -> Self {
        match value {
            Ed448Operation::Verify => Self::ED448_OPERATION_VERIFY,
            Ed448Operation::OpaqueSign => Self::ED448_OPERATION_OPAQUE_SIGN,
            Ed448Operation::SoftwareKeyGeneration => Self::ED448_OPERATION_SOFTWARE_KEY_GENERATION,
            Ed448Operation::SoftwareKeyImport => Self::ED448_OPERATION_SOFTWARE_KEY_IMPORT,
        }
    }
}
impl TryFrom<&CryptoEd448KeyImportRequest> for Ed448Key {
    type Error = CryptoError;
    fn try_from(request: &CryptoEd448KeyImportRequest) -> Result<Self, Self::Error> {
        known_fields(request.__buffa_unknown_fields.is_empty())?;
        super::require_support(Ed448Operation::SoftwareKeyImport)?;
        Self::import(&request.seed)
    }
}
/// Check the exact native operation without inferring support from enum presence.
pub fn require_support(request: &CryptoEd448SupportRequest) -> Result<(), CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    super::require_support(Ed448Operation::try_from(request.operation)?)
}
/// Generate a protected owner; no seed bytes are emitted by this contract.
pub fn generate(request: &CryptoNativeKeyGenerateRequest) -> Result<Ed448Key, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    super::require_support(Ed448Operation::SoftwareKeyGeneration)?;
    Ed448Key::generate()
}
/// Preserve existing injected-entropy behavior and cleanup on partial failure.
pub fn generate_with_rng(
    request: &CryptoNativeKeyGenerateRequest,
    rng: &mut impl crate::key_random::KeyRng,
) -> Result<Ed448Key, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    super::require_support(Ed448Operation::SoftwareKeyGeneration)?;
    Ed448Key::generate_with_rng(rng)
}
fn public_output(bytes: &[u8]) -> Result<CryptoEd448PublicKey, CryptoError> {
    let mut output = CryptoEd448PublicKey::default();
    copy_bytes(&mut output.public_key, bytes)?;
    Ok(output)
}
/// Expose only the owner-associated public key.
pub fn public_key(
    key: &Ed448Key,
    request: &CryptoNativePublicKeyRequest,
) -> Result<CryptoEd448PublicKey, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    public_output(key.public_key())
}
/// Describe signing method support and private seed cleanup.
/// The descriptor is not proof that a key remains valid after explicit zeroization.
pub fn describe_software(key: &Ed448Key) -> Result<CryptoEd448KeyDescriptor, CryptoError> {
    super::require_support(Ed448Operation::Verify)?;
    Ok(CryptoEd448KeyDescriptor {
        public_key: MessageField::some(public_output(key.public_key())?),
        capabilities: MessageField::some(capabilities(
            NativeKeySource::NATIVE_KEY_SOURCE_SOFTWARE_OWNER,
            true,
            false,
            false,
            true,
        )?),
        __buffa_unknown_fields: Default::default(),
    })
}
/// Report only trait-backed capabilities. Public association is authenticated
/// when sign_with_provider validates the produced signature, not by metadata.
pub fn describe_opaque(
    provider: &impl OpaqueEd448Signer,
) -> Result<CryptoEd448KeyDescriptor, CryptoError> {
    super::require_support(Ed448Operation::OpaqueSign)?;
    Ok(CryptoEd448KeyDescriptor {
        public_key: MessageField::some(public_output(provider.public_key())?),
        capabilities: MessageField::some(capabilities(
            NativeKeySource::NATIVE_KEY_SOURCE_OPAQUE_SIGNER,
            true,
            false,
            false,
            false,
        )?),
        __buffa_unknown_fields: Default::default(),
    })
}
/// Ordinary Ed448 signs exact bytes, including a valid empty message.
pub fn sign(
    key: &Ed448Key,
    request: &CryptoEd448OrdinarySignRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let signature = Zeroizing::new(key.sign(&request.message)?);
    let mut output = CryptoNativeSignatureResult::default();
    copy_bytes(&mut output.signature, signature.as_ref())?;
    Ok(output)
}
/// Use the existing opaque path; it checks exact message and key association.
pub fn sign_opaque(
    provider: &impl OpaqueEd448Signer,
    request: &CryptoEd448OrdinarySignRequest,
) -> Result<CryptoNativeSignatureResult, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let signature = Zeroizing::new(super::sign_with_provider(provider, &request.message)?);
    let mut output = CryptoNativeSignatureResult::default();
    copy_bytes(&mut output.signature, signature.as_ref())?;
    Ok(output)
}
/// Verify the ordinary empty-context variant only; unknown modifiers fail closed.
pub fn verify(
    request: &CryptoEd448OrdinaryVerifyRequest,
) -> Result<CryptoNativeVerificationResult, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    super::verify(&request.public_key, &request.message, &request.signature)?;
    Ok(verified())
}
