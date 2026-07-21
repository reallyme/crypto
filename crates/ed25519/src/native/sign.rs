// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey};

const ED25519_SECRET_KEY_LEN: usize = 32;

/// Sign a message using a 32-byte seed.
pub fn sign_ed25519(privkey: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed: &[u8; ED25519_SECRET_KEY_LEN] =
        privkey.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let signing_key = SigningKey::from(seed);

    let sig: Signature = signing_key.sign(message);
    Ok(sig.to_bytes().to_vec())
}
