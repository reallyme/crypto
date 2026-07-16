// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use p256::ecdsa::SigningKey;
use p256::SecretKey;
use zeroize::{Zeroize, Zeroizing};

/// Derive a P-256 keypair from an existing 32-byte secret scalar.
///
/// This is intentionally named `from_secret_key`, not `from_seed`: the input
/// is already the private scalar material and must be a valid P-256 secret.
/// Random production key generation remains a separate API.
pub fn generate_p256_keypair_from_secret_key(
    secret_key: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let secret = SecretKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let signing_key = SigningKey::from(&secret);
    let verifying_key = signing_key.verifying_key();

    let mut secret_stack = secret.to_bytes();
    let secret_bytes = Zeroizing::new(secret_stack.to_vec());
    secret_stack.zeroize();
    let public_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec();

    Ok((public_bytes, secret_bytes))
}
