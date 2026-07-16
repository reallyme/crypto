// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::multikey;
use crate::registry;
use crate::AlgorithmError;
use crypto_core::Algorithm;

/// A generated keypair together with the multikey-encoded public key.
pub struct GeneratedKeypair {
    /// Raw public key bytes.
    pub public_key: Vec<u8>,
    /// Secret half of the keypair; zeroized when the struct is dropped.
    pub secret_key: Zeroizing<Vec<u8>>,
    /// The public key encoded as a `z`-prefixed multikey string.
    pub public_key_multikey: String,
}

/// Generate a keypair and multikey-encode the public key
pub fn generate_multikey_keypair(alg: Algorithm) -> Result<GeneratedKeypair, AlgorithmError> {
    let (public, secret) = registry::generate_keypair(alg)?;
    let multikey = multikey::public_key_to_multikey(alg, &public)?;

    Ok(GeneratedKeypair {
        public_key: public,
        secret_key: secret,
        public_key_multikey: multikey,
    })
}
