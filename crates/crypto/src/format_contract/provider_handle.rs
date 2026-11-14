// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoP256SecureEnclaveHandleDecodeRequest, CryptoP256SecureEnclaveHandleDecodeResult,
    CryptoP256SecureEnclaveHandleEncodeRequest, CryptoP256SecureEnclaveHandleEncodeResult,
};

/// Preserve the existing prefix format, including arbitrary binary/empty tags.
/// This format operation neither queries a provider nor validates its handle.
pub fn encode_p256_handle(
    request: &CryptoP256SecureEnclaveHandleEncodeRequest,
) -> Result<CryptoP256SecureEnclaveHandleEncodeResult, CryptoError> {
    #[cfg(any(feature = "p256", feature = "ecdsa-explicit"))]
    {
        let encoded = zeroize::Zeroizing::new(crypto_p256::encode_se_handle(&request.tag)?);
        let mut output = CryptoP256SecureEnclaveHandleEncodeResult::default();
        crate::native_contract_support::copy_bytes(&mut output.handle, &encoded)?;
        Ok(output)
    }
    #[cfg(not(any(feature = "p256", feature = "ecdsa-explicit")))]
    {
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

/// Preserve non-matching versus matching-empty handle semantics. The borrowed
/// native tag is copied only after installing its optional clearing DTO owner.
pub fn decode_p256_handle(
    request: &CryptoP256SecureEnclaveHandleDecodeRequest,
) -> Result<CryptoP256SecureEnclaveHandleDecodeResult, CryptoError> {
    #[cfg(any(feature = "p256", feature = "ecdsa-explicit"))]
    {
        let mut output = CryptoP256SecureEnclaveHandleDecodeResult::default();
        if let Some(tag) = crypto_p256::decode_se_handle(&request.handle) {
            let storage = output.tag.insert(Vec::new().into());
            crate::native_contract_support::copy_bytes(storage, tag)?;
        }
        Ok(output)
    }
    #[cfg(not(any(feature = "p256", feature = "ecdsa-explicit")))]
    {
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}
