// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared protected output construction for standalone native contracts.

use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeKeyCapabilities, CryptoNativeVerificationResult, CryptoVerificationStatus,
    NativeKeySource,
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
            return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
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

pub(crate) fn verified() -> CryptoNativeVerificationResult {
    CryptoNativeVerificationResult {
        status: CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID.into(),
        __buffa_unknown_fields: Default::default(),
    }
}
