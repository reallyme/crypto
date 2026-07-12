// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "hmac")]
use crate::traits::MacAlgorithmAdapter;
use crate::traits::MacParams;
use crate::AlgorithmError;
use crypto_core::MacAlgorithm;

/// Computes a MAC tag using the selected MAC algorithm.
pub fn mac_authenticate(
    alg: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(not(feature = "hmac"))]
    let _ = (params, message);

    match alg {
        MacAlgorithm::HmacSha256 => {
            #[cfg(feature = "hmac")]
            {
                crate::algorithms::hmac::HmacSha256Algo::authenticate(params, message)
            }
            #[cfg(not(feature = "hmac"))]
            {
                Err(AlgorithmError::UnsupportedMacAlgorithm(alg))
            }
        }
        MacAlgorithm::HmacSha512 => {
            #[cfg(feature = "hmac")]
            {
                crate::algorithms::hmac::HmacSha512Algo::authenticate(params, message)
            }
            #[cfg(not(feature = "hmac"))]
            {
                Err(AlgorithmError::UnsupportedMacAlgorithm(alg))
            }
        }
    }
}

/// Verifies a MAC tag using the selected MAC algorithm.
pub fn mac_verify(
    alg: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
    tag: &[u8],
) -> Result<(), AlgorithmError> {
    #[cfg(not(feature = "hmac"))]
    let _ = (params, message, tag);

    match alg {
        MacAlgorithm::HmacSha256 => {
            #[cfg(feature = "hmac")]
            {
                crate::algorithms::hmac::HmacSha256Algo::verify(params, message, tag)
            }
            #[cfg(not(feature = "hmac"))]
            {
                Err(AlgorithmError::UnsupportedMacAlgorithm(alg))
            }
        }
        MacAlgorithm::HmacSha512 => {
            #[cfg(feature = "hmac")]
            {
                crate::algorithms::hmac::HmacSha512Algo::verify(params, message, tag)
            }
            #[cfg(not(feature = "hmac"))]
            {
                Err(AlgorithmError::UnsupportedMacAlgorithm(alg))
            }
        }
    }
}
