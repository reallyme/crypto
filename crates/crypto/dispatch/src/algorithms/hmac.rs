// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::traits::{MacAlgorithmAdapter, MacParams};
use crate::AlgorithmError;
use crypto_core::MacAlgorithm;

/// HMAC-SHA-256 adapter.
pub struct HmacSha256Algo;

/// HMAC-SHA-512 adapter.
pub struct HmacSha512Algo;

impl MacAlgorithmAdapter for HmacSha256Algo {
    const ALG: MacAlgorithm = MacAlgorithm::HmacSha256;

    fn authenticate(params: &MacParams<'_>, message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        authenticate(Self::ALG, params, message)
    }

    fn verify(params: &MacParams<'_>, message: &[u8], tag: &[u8]) -> Result<(), AlgorithmError> {
        verify(Self::ALG, params, message, tag)
    }
}

impl MacAlgorithmAdapter for HmacSha512Algo {
    const ALG: MacAlgorithm = MacAlgorithm::HmacSha512;

    fn authenticate(params: &MacParams<'_>, message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        authenticate(Self::ALG, params, message)
    }

    fn verify(params: &MacParams<'_>, message: &[u8], tag: &[u8]) -> Result<(), AlgorithmError> {
        verify(Self::ALG, params, message, tag)
    }
}

fn authenticate(
    algorithm: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
    {
        let key = crypto_hmac::HmacKey::from_slice(params.key)?;
        let tag = crypto_hmac::authenticate(algorithm, &key, message)?;
        Ok(tag.into_vec())
    }

    #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
    {
        let _ = (params, message);
        Err(AlgorithmError::UnsupportedMacAlgorithm(algorithm))
    }
}

fn verify(
    algorithm: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
    tag: &[u8],
) -> Result<(), AlgorithmError> {
    #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
    {
        let key = crypto_hmac::HmacKey::from_slice(params.key)?;
        crypto_hmac::verify(algorithm, &key, message, tag)?;
        Ok(())
    }

    #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
    {
        let _ = (params, message, tag);
        Err(AlgorithmError::UnsupportedMacAlgorithm(algorithm))
    }
}
