// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![cfg(feature = "native")]

use crypto_core::CryptoError;
use crypto_secp256k1::derive_secp256k1_shared_secret;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::SecretKey;

fn uncompressed_public_key(secret: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let secret_key = SecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
    Ok(secret_key
        .public_key()
        .as_affine()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec())
}

#[test]
fn secp256k1_ecdh_agrees_for_both_parties() -> Result<(), CryptoError> {
    let secret_a = [0x11_u8; 32];
    let secret_b = [0x22_u8; 32];
    let public_a = uncompressed_public_key(&secret_a)?;
    let public_b = uncompressed_public_key(&secret_b)?;

    let shared_a = derive_secp256k1_shared_secret(&secret_a, &public_b)?;
    let shared_b = derive_secp256k1_shared_secret(&secret_b, &public_a)?;

    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    assert!(shared_a.as_bytes().iter().any(|byte| *byte != 0));
    Ok(())
}

#[test]
fn secp256k1_ecdh_rejects_invalid_private_keys() -> Result<(), CryptoError> {
    let public_key = uncompressed_public_key(&[0x22_u8; 32])?;

    assert!(derive_secp256k1_shared_secret(&[], &public_key).is_err());
    assert!(derive_secp256k1_shared_secret(&[0_u8; 32], &public_key).is_err());
    assert!(derive_secp256k1_shared_secret(&[0xff_u8; 32], &public_key).is_err());
    Ok(())
}

#[test]
fn secp256k1_ecdh_requires_valid_uncompressed_public_keys() {
    let secret_key = [0x11_u8; 32];
    let compressed = [0x02_u8; 33];
    let malformed = [0x04_u8; 65];

    assert!(derive_secp256k1_shared_secret(&secret_key, &compressed).is_err());
    assert!(derive_secp256k1_shared_secret(&secret_key, &malformed).is_err());
}
