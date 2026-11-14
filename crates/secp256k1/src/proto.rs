// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone raw secp256k1 agreement using the unchanged native contract.
//!
//! This adapter does not infer a curve, expand SEC1 encodings, apply a KDF or
//! add an executable root operation. Input owners retain caller bytes exactly.

use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeAgreementResult, CryptoSecp256k1AgreementRequest,
};

/// Derive the native fixed-width raw x-coordinate and copy it only through the
/// initialized final clearing result. Native key/point errors pass through;
/// unknown modifiers are rejected before key validation or secret derivation.
pub fn derive_shared_secret(
    request: &CryptoSecp256k1AgreementRequest,
) -> Result<CryptoNativeAgreementResult, CryptoError> {
    let secret =
        crate::derive_secp256k1_shared_secret(&request.private_key, &request.peer_public_key_sec1)?;
    let mut result = CryptoNativeAgreementResult::default();
    result
        .shared_secret
        .try_reserve_exact(secret.as_bytes().len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    result.shared_secret.resize(secret.as_bytes().len(), 0)?;
    result.shared_secret.copy_from_slice(secret.as_bytes());
    Ok(result)
}
