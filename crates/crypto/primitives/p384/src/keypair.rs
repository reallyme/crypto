// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use p384::ecdsa::SigningKey;
use p384::elliptic_curve::Generate;
use p384::SecretKey;
use zeroize::{Zeroize, Zeroizing};

/// Generate a P-384 keypair.
///
/// The public key is returned as compressed SEC1; the secret key is the raw
/// scalar in a zeroizing heap buffer owned by the caller.
pub fn generate_p384_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let secret_key = SecretKey::generate();
    let signing_key = SigningKey::from(&secret_key);
    let verifying_key = signing_key.verifying_key();

    let mut secret_stack = secret_key.to_bytes();
    let secret_bytes = Zeroizing::new(secret_stack.to_vec());
    secret_stack.zeroize();
    let public_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec();

    (public_bytes, secret_bytes)
}

/// Derive a P-384 keypair from an existing 48-byte secret scalar.
///
/// This is intentionally named `from_secret_key`, not `from_seed`: the input
/// is already the private scalar material and must be a valid P-384 secret.
pub fn generate_p384_keypair_from_secret_key(
    secret_key: &[u8; 48],
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
