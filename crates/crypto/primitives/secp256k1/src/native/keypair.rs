// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::Generate;
use k256::SecretKey;
use zeroize::{Zeroize, Zeroizing};

/// Generate a secp256k1 keypair.
///
/// Returns:
/// - public key: 33-byte compressed SEC1
/// - secret key: 32-byte scalar, in a zeroizing wrapper so it is wiped when
///   the caller drops it
pub fn generate_secp256k1_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let sk = SecretKey::generate();

    let signing_key = SigningKey::from(&sk);
    let verifying_key = signing_key.verifying_key();

    // Wipe the temporary stack copy of the scalar after moving it to the heap.
    let mut secret_stack = sk.to_bytes();
    let secret_bytes = Zeroizing::new(secret_stack.to_vec()); // 32 bytes
    secret_stack.zeroize();
    let public_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec(); // 33 bytes (compressed)

    (public_bytes, secret_bytes)
}

/// Derive a secp256k1 keypair from an existing 32-byte secret scalar.
///
/// This is intentionally named `from_secret_key`, not `from_seed`: the input
/// is already the private scalar material and must be a valid secp256k1 secret.
pub fn generate_secp256k1_keypair_from_secret_key(
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
