// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::traits::HashDigestAlgorithm;
use crate::AlgorithmError;
use crypto_core::HashAlgorithm;

/// SHA-384 (SHA-2) hash adapter.
pub struct Sha2_384Algo;

/// SHA-512 (SHA-2) hash adapter.
pub struct Sha2_512Algo;

impl HashDigestAlgorithm for Sha2_384Algo {
    const ALG: HashAlgorithm = HashAlgorithm::Sha2_384;

    fn digest(message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        let digest = crypto_sha2::digest_sha2_384(message);
        Ok(digest.as_bytes().to_vec())
    }
}

impl HashDigestAlgorithm for Sha2_512Algo {
    const ALG: HashAlgorithm = HashAlgorithm::Sha2_512;

    fn digest(message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        let digest = crypto_sha2::digest_sha2_512(message);
        Ok(digest.as_bytes().to_vec())
    }
}
