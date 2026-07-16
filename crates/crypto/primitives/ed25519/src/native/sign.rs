// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey};

/// Sign a message using a 32-byte seed or 64-byte expanded key.
pub fn sign_ed25519(privkey: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signing_key = match privkey.len() {
        // 32-byte private seed
        32 => {
            let seed: &[u8; 32] = privkey.try_into().map_err(|_| CryptoError::InvalidKey)?;
            SigningKey::from(seed)
        }

        // 64-byte expanded key (seed || pubkey)
        64 => {
            let seed: &[u8; 32] = (&privkey[0..32])
                .try_into()
                .map_err(|_| CryptoError::InvalidKey)?;
            SigningKey::from(seed)
        }

        _ => return Err(CryptoError::InvalidKey),
    };

    let sig: Signature = signing_key.sign(message);
    Ok(sig.to_bytes().to_vec())
}
