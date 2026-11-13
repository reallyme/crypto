// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared protected output construction for standalone native contracts.

use crypto_core::CryptoError;
#[cfg(any(
    feature = "ecdsa-explicit",
    feature = "ed448",
    feature = "prime-groups"
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeKeyCapabilities, NativeKeySource,
};

pub(crate) fn known_fields(empty: bool) -> Result<(), CryptoError> {
    if empty {
        Ok(())
    } else {
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

// The destination must already belong to a clearing generated message. Install
// capacity and initialized length before copying any secret or privacy bytes.
#[cfg(any(
    feature = "ecdsa-explicit",
    feature = "ed448",
    feature = "prime-groups",
    feature = "key-identifier-sha1",
    feature = "p256",
    feature = "secp256k1",
    feature = "ed25519",
    all(
        any(feature = "native", feature = "wasm"),
        any(
            feature = "x25519",
            feature = "p384",
            feature = "p521",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "ml-kem-512",
            feature = "ml-kem-768",
            feature = "ml-kem-1024",
            feature = "slh-dsa",
            feature = "x-wing"
        )
    )
))]
pub(crate) fn copy_bytes(destination: &mut Vec<u8>, source: &[u8]) -> Result<(), CryptoError> {
    if !destination.is_empty() {
        return Err(CryptoError::BACKEND_INVALID_STATE);
    }
    destination
        .try_reserve_exact(source.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    destination.resize(source.len(), 0);
    destination.copy_from_slice(source);
    Ok(())
}

#[cfg(any(
    feature = "ecdsa-explicit",
    feature = "ed448",
    feature = "prime-groups"
))]
pub(crate) fn capabilities(
    source: NativeKeySource,
    signing: bool,
    agreement: bool,
    private_export: bool,
    explicit_zeroize: bool,
) -> Result<CryptoNativeKeyCapabilities, CryptoError> {
    let opaque = match source {
        NativeKeySource::NATIVE_KEY_SOURCE_SOFTWARE_OWNER => false,
        NativeKeySource::NATIVE_KEY_SOURCE_OPAQUE_SIGNER => true,
        NativeKeySource::NATIVE_KEY_SOURCE_UNSPECIFIED => {
            return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
    };
    Ok(CryptoNativeKeyCapabilities {
        source: source.into(),
        supports_signing: signing,
        supports_agreement: agreement,
        exposes_private_bytes: private_export,
        supports_explicit_zeroize: explicit_zeroize,
        zeroizes_private_storage_on_drop: !opaque,
        provider_managed_cleanup: opaque,
        __buffa_unknown_fields: Default::default(),
    })
}

#[cfg(any(feature = "ecdsa-explicit", feature = "ed448"))]
pub(crate) fn verified(
) -> crypto_proto::generated::proto::reallyme::crypto::v1::CryptoNativeVerificationResult {
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        CryptoNativeVerificationResult, CryptoVerificationStatus,
    };
    CryptoNativeVerificationResult {
        status: CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID.into(),
        __buffa_unknown_fields: Default::default(),
    }
}
