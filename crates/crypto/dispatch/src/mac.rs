// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::algorithms::hmac::{HmacSha256Algo, HmacSha512Algo};
use crate::traits::{MacAlgorithmAdapter, MacParams};
use crate::AlgorithmError;
use crypto_core::MacAlgorithm;

/// Computes a MAC tag using the selected MAC algorithm.
pub fn mac_authenticate(
    alg: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
) -> Result<Vec<u8>, AlgorithmError> {
    match alg {
        MacAlgorithm::HmacSha256 => HmacSha256Algo::authenticate(params, message),
        MacAlgorithm::HmacSha512 => HmacSha512Algo::authenticate(params, message),
    }
}

/// Verifies a MAC tag using the selected MAC algorithm.
pub fn mac_verify(
    alg: MacAlgorithm,
    params: &MacParams<'_>,
    message: &[u8],
    tag: &[u8],
) -> Result<(), AlgorithmError> {
    match alg {
        MacAlgorithm::HmacSha256 => HmacSha256Algo::verify(params, message, tag),
        MacAlgorithm::HmacSha512 => HmacSha512Algo::verify(params, message, tag),
    }
}
