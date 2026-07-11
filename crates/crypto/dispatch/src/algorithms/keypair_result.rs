// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::Algorithm;
use zeroize::Zeroizing;

use crate::AlgorithmError;

/// Normalized keypair shape: (public_key, secret_key). The secret half is
/// always carried in a zeroizing wrapper.
pub(crate) type AlgorithmKeypair = (Vec<u8>, Zeroizing<Vec<u8>>);

#[allow(dead_code)]
pub(crate) trait KeypairResultExt {
    fn into_algorithm_keypair(self, alg: Algorithm) -> Result<AlgorithmKeypair, AlgorithmError>;
}

impl KeypairResultExt for AlgorithmKeypair {
    fn into_algorithm_keypair(self, _alg: Algorithm) -> Result<AlgorithmKeypair, AlgorithmError> {
        Ok(self)
    }
}

impl<E> KeypairResultExt for Result<AlgorithmKeypair, E> {
    fn into_algorithm_keypair(self, alg: Algorithm) -> Result<AlgorithmKeypair, AlgorithmError> {
        self.map_err(|_| AlgorithmError::InvalidKey(alg))
    }
}
