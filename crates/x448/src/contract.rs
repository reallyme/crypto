// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone X448 contracts preserve native clearing owners and raw bytes.
//! The optional proto feature never enables native execution by itself.

use crate::{X448PrivateKey, X448PublicKey, X448SharedSecret, X448_PRIVATE_KEY_LEN};
use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeAgreementResult, CryptoNativeKeyCapabilities, CryptoNativeKeyGenerateRequest,
    CryptoNativePublicKeyRequest, CryptoX448AgreementRequest, CryptoX448KeyDescriptor,
    CryptoX448PrivateKeyInput, CryptoX448PublicKey, NativeKeySource,
};

impl TryFrom<&CryptoX448PrivateKeyInput> for X448PrivateKey {
    type Error = CryptoError;
    fn try_from(request: &CryptoX448PrivateKeyInput) -> Result<Self, Self::Error> {
        Self::from_bytes(&request.scalar)
    }
}
impl TryFrom<&CryptoX448PublicKey> for X448PublicKey {
    type Error = CryptoError;
    fn try_from(value: &CryptoX448PublicKey) -> Result<Self, Self::Error> {
        Self::from_bytes(&value.u_coordinate)
    }
}
impl TryFrom<&X448PublicKey> for CryptoX448PublicKey {
    type Error = CryptoError;
    fn try_from(value: &X448PublicKey) -> Result<Self, Self::Error> {
        Ok(Self {
            u_coordinate: crypto_proto::SecretBytes::try_from_slice(value.as_bytes())?,
        })
    }
}
/// Generate the existing protected private/public pair without private export.
pub fn generate(
    _: &CryptoNativeKeyGenerateRequest,
) -> Result<(X448PrivateKey, X448PublicKey), CryptoError> {
    crate::generate_x448_keypair()
}
/// Derive the existing pair from a borrowed fixed-size caller seed.
pub fn generate_from_seed(
    request: &CryptoX448PrivateKeyInput,
) -> Result<(X448PrivateKey, X448PublicKey), CryptoError> {
    let seed = <&[u8; X448_PRIVATE_KEY_LEN]>::try_from(request.scalar.as_slice())
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    crate::generate_x448_keypair_from_seed(seed)
}
/// Borrow the owner-associated public key without serializing its scalar.
pub fn public_key(
    key: &X448PrivateKey,
    _: &CryptoNativePublicKeyRequest,
) -> Result<CryptoX448PublicKey, CryptoError> {
    CryptoX448PublicKey::try_from(&X448PublicKey::from(key))
}
/// Report the published native API accurately. In particular, X448 already
/// has an explicit private-byte borrow; this descriptor adds no new export.
pub fn describe(key: &X448PrivateKey) -> Result<CryptoX448KeyDescriptor, CryptoError> {
    let capabilities = CryptoNativeKeyCapabilities {
        source: NativeKeySource::NATIVE_KEY_SOURCE_SOFTWARE_OWNER.into(),
        supports_signing: false,
        supports_agreement: true,
        exposes_private_bytes: true,
        supports_explicit_zeroize: true,
        zeroizes_private_storage_on_drop: true,
        provider_managed_cleanup: false,
    };
    Ok(CryptoX448KeyDescriptor {
        public_key: MessageField::some(CryptoX448PublicKey::try_from(&X448PublicKey::from(key))?),
        capabilities: MessageField::some(capabilities),
    })
}
/// Agreement retains low-order/non-contributory rejection and returns its
/// existing clearing native owner, without KDF or byte-order changes.
pub fn agree(
    key: &X448PrivateKey,
    request: &CryptoX448AgreementRequest,
) -> Result<X448SharedSecret, CryptoError> {
    let public = X448PublicKey::try_from(
        request
            .peer_public_key
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    crate::derive_x448_shared_secret(key, public)
}
/// Explicitly copy a shared secret into an already clearing transport owner.
pub fn agreement_result(
    secret: &X448SharedSecret,
) -> Result<CryptoNativeAgreementResult, CryptoError> {
    Ok(CryptoNativeAgreementResult {
        shared_secret: crypto_proto::SecretBytes::try_from_slice(secret.as_bytes())?,
    })
}
