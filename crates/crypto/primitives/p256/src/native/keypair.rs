// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use p256::SecretKey;
use zeroize::{Zeroize, Zeroizing};

/// Generate a P-256 keypair.
///
/// Returns:
/// - public key: 33-byte compressed SEC1
/// - secret key: 32-byte scalar, in a zeroizing wrapper so it is wiped when
///   the caller drops it
pub fn generate_p256_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let sk = SecretKey::generate();

    let signing_key = SigningKey::from(&sk);
    let verifying_key = signing_key.verifying_key();

    // Wipe the temporary stack copy of the scalar after moving it to the heap.
    let mut secret_stack = sk.to_bytes();
    let secret_bytes = Zeroizing::new(secret_stack.to_vec()); // 32 bytes
    secret_stack.zeroize();
    let public_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec(); // 33 bytes (compressed)

    Ok((public_bytes, secret_bytes))
}
