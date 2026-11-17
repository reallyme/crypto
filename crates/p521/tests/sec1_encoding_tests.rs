// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(any(feature = "native", feature = "wasm"))]

use crypto_core::CryptoError;
use crypto_p521::{
    decompress_public_key, derive_p521_shared_secret, generate_p521_keypair_from_secret_key,
    sign_p521_der_prehash, verify_p521_der_prehash,
};
use zeroize::Zeroizing;

#[test]
fn verify_and_ecdh_require_standard_sec1_encodings() -> Result<(), CryptoError> {
    const MESSAGE: &[u8] = b"strict SEC1 public key boundary";
    for scalar in [1, 2] {
        let mut secret = Zeroizing::new([0u8; 66]);
        *secret
            .last_mut()
            .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)? = scalar;
        let (compressed, _owned_secret) = generate_p521_keypair_from_secret_key(&secret)?;
        let uncompressed = decompress_public_key(&compressed)?;
        let signature = sign_p521_der_prehash(secret.as_slice(), MESSAGE)?;
        let expected = derive_p521_shared_secret(secret.as_slice(), &compressed)?;
        for public_key in [&compressed, &uncompressed] {
            verify_p521_der_prehash(&signature, MESSAGE, public_key)?;
            let shared = derive_p521_shared_secret(secret.as_slice(), public_key)?;
            assert_eq!(shared.as_slice(), expected.as_slice());
        }

        // These retain a valid x-coordinate, including the backend's 0x05
        // compact alias. Rejection must be a key error, never a signature error.
        for prefix in [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
            let mut invalid = compressed.clone();
            invalid[0] = prefix;
            assert_eq!(
                verify_p521_der_prehash(&signature, MESSAGE, &invalid),
                Err(CryptoError::PRIMITIVE_INVALID_KEY),
            );
            assert_eq!(
                derive_p521_shared_secret(secret.as_slice(), &invalid).err(),
                Some(CryptoError::PRIMITIVE_INVALID_KEY),
            );
        }

        let mut truncated = compressed.clone();
        truncated.pop();
        let mut oversized = compressed.clone();
        oversized.push(0);
        let mut invalid_point = compressed.clone();
        invalid_point.fill(0xff);
        invalid_point[0] = 0x02;
        let mut hybrid = uncompressed;
        hybrid[0] = 0x06;
        for invalid in [Vec::new(), truncated, oversized, invalid_point, hybrid] {
            assert_eq!(
                verify_p521_der_prehash(&signature, MESSAGE, &invalid),
                Err(CryptoError::PRIMITIVE_INVALID_KEY),
            );
            assert_eq!(
                derive_p521_shared_secret(secret.as_slice(), &invalid).err(),
                Some(CryptoError::PRIMITIVE_INVALID_KEY),
            );
        }
    }
    Ok(())
}
