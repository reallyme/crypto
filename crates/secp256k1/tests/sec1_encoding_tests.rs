// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(any(feature = "native", feature = "wasm"))]

use crypto_core::CryptoError;
use crypto_secp256k1::{
    decompress_public_key, derive_secp256k1_shared_secret,
    generate_secp256k1_keypair_from_secret_key, sign_secp256k1, verify_secp256k1,
};
use zeroize::Zeroizing;

#[test]
fn verify_decompress_and_ecdh_reject_compact_point_aliases() -> Result<(), CryptoError> {
    const MESSAGE: &[u8] = b"strict secp256k1 SEC1 boundary";
    for scalar in [1, 2] {
        let mut secret = Zeroizing::new([0u8; 32]);
        *secret
            .last_mut()
            .ok_or(CryptoError::PRIMITIVE_INVALID_KEY)? = scalar;
        let (compressed, _owned_secret) = generate_secp256k1_keypair_from_secret_key(&secret)?;
        let (x, y) = decompress_public_key(&compressed)?;
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);
        let signature = sign_secp256k1(secret.as_slice(), MESSAGE)?;
        for public_key in [&compressed, &uncompressed] {
            verify_secp256k1(&signature, MESSAGE, public_key)?;
        }
        derive_secp256k1_shared_secret(secret.as_slice(), &uncompressed)?;
        // This DHKEM boundary intentionally accepts only uncompressed SEC1.
        assert_eq!(
            derive_secp256k1_shared_secret(secret.as_slice(), &compressed).err(),
            Some(CryptoError::PRIMITIVE_INVALID_KEY),
        );

        for prefix in [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
            let mut invalid = compressed.clone();
            invalid[0] = prefix;
            assert_eq!(
                verify_secp256k1(&signature, MESSAGE, &invalid),
                Err(CryptoError::PRIMITIVE_INVALID_KEY),
            );
            assert_eq!(
                decompress_public_key(&invalid),
                Err(CryptoError::PRIMITIVE_INVALID_KEY),
            );
            assert_eq!(
                derive_secp256k1_shared_secret(secret.as_slice(), &invalid).err(),
                Some(CryptoError::PRIMITIVE_INVALID_KEY),
            );
        }
        let mut truncated = compressed.clone();
        truncated.pop();
        let mut oversized = compressed.clone();
        oversized.push(0);
        let mut invalid_point = compressed;
        invalid_point.fill(0xff);
        invalid_point[0] = 0x02;
        let mut hybrid = uncompressed;
        hybrid[0] = 0x06;
        for invalid in [Vec::new(), truncated, oversized, invalid_point, hybrid] {
            assert_eq!(
                verify_secp256k1(&signature, MESSAGE, &invalid),
                Err(CryptoError::PRIMITIVE_INVALID_KEY),
            );
            assert_eq!(
                derive_secp256k1_shared_secret(secret.as_slice(), &invalid).err(),
                Some(CryptoError::PRIMITIVE_INVALID_KEY),
            );
        }
    }
    Ok(())
}
