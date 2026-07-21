// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use crypto_core::{CryptoError, KdfFailureKind};
use crypto_pbkdf2::{
    derive_key, Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request, Pbkdf2Salt,
    PBKDF2_MAX_ITERATIONS, PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MODERN_MIN_ITERATIONS,
};
use hex_literal::hex;

#[test]
fn pbkdf2_hmac_sha256_matches_known_answer() {
    let prf = Pbkdf2Prf::HmacSha256;
    let password = Pbkdf2Password::from_slice(b"password", prf).unwrap();
    let salt = Pbkdf2Salt::from_slice(b"salt", prf).unwrap();
    let iterations = Pbkdf2Iterations::from_u32(1, prf).unwrap();

    let output = derive_key(&Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len: 32,
    })
    .unwrap();

    assert_eq!(
        output.as_bytes(),
        hex!("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    );
}

#[test]
fn pbkdf2_hmac_sha512_matches_known_answer() {
    let prf = Pbkdf2Prf::HmacSha512;
    let password = Pbkdf2Password::from_slice(b"password", prf).unwrap();
    let salt = Pbkdf2Salt::from_slice(b"salt", prf).unwrap();
    let iterations = Pbkdf2Iterations::from_u32(1, prf).unwrap();

    let output = derive_key(&Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len: 64,
    })
    .unwrap();

    assert_eq!(
        output.as_bytes(),
        hex!(
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
            "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        )
    );
}

#[test]
fn invalid_inputs_are_rejected() {
    let prf = Pbkdf2Prf::HmacSha256;
    assert!(matches!(
        Pbkdf2Password::from_slice(b"", prf),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidSecretLength,
            ..
        })
    ));
    assert!(matches!(
        Pbkdf2Salt::from_slice(b"", prf),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidSaltLength,
            ..
        })
    ));
    assert!(matches!(
        Pbkdf2Iterations::from_u32(0, prf),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidIterationCount,
            ..
        })
    ));
    assert!(matches!(
        Pbkdf2Iterations::from_u32(PBKDF2_MAX_ITERATIONS + 1, prf),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidIterationCount,
            ..
        })
    ));

    let password = Pbkdf2Password::from_slice(b"password", prf).unwrap();
    let salt = Pbkdf2Salt::from_slice(b"salt", prf).unwrap();
    let iterations = Pbkdf2Iterations::from_u32(1, prf).unwrap();
    assert!(matches!(
        derive_key(&Pbkdf2Request {
            prf,
            password: &password,
            salt: &salt,
            iterations,
            output_len: 0,
        }),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidOutputLength,
            ..
        })
    ));
    assert!(matches!(
        derive_key(&Pbkdf2Request {
            prf,
            password: &password,
            salt: &salt,
            iterations,
            output_len: PBKDF2_MAX_OUTPUT_LENGTH + 1,
        }),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidOutputLength,
            ..
        })
    ));
}

#[test]
fn modern_iteration_constructor_enforces_public_policy_bounds() {
    let prf = Pbkdf2Prf::HmacSha256;
    assert!(matches!(
        Pbkdf2Iterations::from_u32_modern(PBKDF2_MODERN_MIN_ITERATIONS - 1, prf),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidIterationCount,
            ..
        })
    ));
    assert_eq!(
        Pbkdf2Iterations::from_u32_modern(PBKDF2_MODERN_MIN_ITERATIONS, prf)
            .unwrap()
            .as_u32(),
        PBKDF2_MODERN_MIN_ITERATIONS
    );
    assert_eq!(
        Pbkdf2Iterations::from_u32_modern(PBKDF2_MAX_ITERATIONS, prf)
            .unwrap()
            .as_u32(),
        PBKDF2_MAX_ITERATIONS
    );
    assert!(matches!(
        Pbkdf2Iterations::from_u32_modern(PBKDF2_MAX_ITERATIONS + 1, prf),
        Err(CryptoError::Kdf {
            kind: KdfFailureKind::InvalidIterationCount,
            ..
        })
    ));
}

#[test]
fn derived_key_ownership_transfer_reuses_the_zeroizing_allocation() {
    let prf = Pbkdf2Prf::HmacSha256;
    let password = Pbkdf2Password::from_slice(b"password", prf).unwrap();
    let salt = Pbkdf2Salt::from_slice(b"salt", prf).unwrap();
    let iterations = Pbkdf2Iterations::from_u32(1, prf).unwrap();
    let output = derive_key(&Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len: 32,
    })
    .unwrap();
    let allocation = output.as_bytes().as_ptr();

    let owned = output.into_zeroizing();

    assert_eq!(owned.as_ptr(), allocation);
}
