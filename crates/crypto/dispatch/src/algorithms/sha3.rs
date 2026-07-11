// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::traits::HashDigestAlgorithm;
use crate::AlgorithmError;
use crypto_core::HashAlgorithm;

/// SHA3-224 hash adapter.
pub struct Sha3_224Algo;

/// SHA3-384 hash adapter.
pub struct Sha3_384Algo;

/// SHA3-512 hash adapter.
pub struct Sha3_512Algo;

impl HashDigestAlgorithm for Sha3_224Algo {
    const ALG: HashAlgorithm = HashAlgorithm::Sha3_224;

    fn digest(message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        let digest = crypto_sha3::digest_sha3_224(message);
        Ok(digest.as_bytes().to_vec())
    }
}

impl HashDigestAlgorithm for Sha3_384Algo {
    const ALG: HashAlgorithm = HashAlgorithm::Sha3_384;

    fn digest(message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        let digest = crypto_sha3::digest_sha3_384(message);
        Ok(digest.as_bytes().to_vec())
    }
}

impl HashDigestAlgorithm for Sha3_512Algo {
    const ALG: HashAlgorithm = HashAlgorithm::Sha3_512;

    fn digest(message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        let digest = crypto_sha3::digest_sha3_512(message);
        Ok(digest.as_bytes().to_vec())
    }
}
