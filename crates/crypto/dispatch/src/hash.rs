// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::algorithms::sha2::{Sha2_384Algo, Sha2_512Algo};
use crate::algorithms::sha2_256::Sha2_256Algo;
use crate::algorithms::sha3::{Sha3_224Algo, Sha3_384Algo, Sha3_512Algo};
use crate::algorithms::sha3_256::Sha3_256Algo;
use crate::traits::HashDigestAlgorithm;
use crate::AlgorithmError;
use crypto_core::HashAlgorithm;

/// Compute a digest using the selected hash algorithm.
pub fn hash_digest(alg: HashAlgorithm, message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    match alg {
        HashAlgorithm::Sha2_256 => Sha2_256Algo::digest(message),
        HashAlgorithm::Sha2_384 => Sha2_384Algo::digest(message),
        HashAlgorithm::Sha2_512 => Sha2_512Algo::digest(message),
        HashAlgorithm::Sha3_224 => Sha3_224Algo::digest(message),
        HashAlgorithm::Sha3_256 => Sha3_256Algo::digest(message),
        HashAlgorithm::Sha3_384 => Sha3_384Algo::digest(message),
        HashAlgorithm::Sha3_512 => Sha3_512Algo::digest(message),
    }
}
