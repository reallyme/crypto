// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::traits::HashDigestAlgorithm;
use crate::AlgorithmError;
use crypto_core::HashAlgorithm;

/// SHA-256 (SHA-2) hash adapter.
pub struct Sha2_256Algo;

impl HashDigestAlgorithm for Sha2_256Algo {
    const ALG: HashAlgorithm = HashAlgorithm::Sha2_256;

    fn digest(message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        let digest = crypto_sha2_256::digest(message);
        Ok(digest.as_bytes().to_vec())
    }
}
