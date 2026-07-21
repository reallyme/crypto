// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "argon2id",
    feature = "concat-kdf",
    feature = "hkdf",
    feature = "kmac",
    feature = "pbkdf2",
    feature = "sha3"
))]
#![allow(clippy::expect_used)]

//! Operation-owner tests for KDF routes.

use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};

#[test]
fn pbkdf2_operation_matches_root_facade_and_rejects_invalid_input() {
    let prf = reallyme_crypto::pbkdf2::Pbkdf2Prf::HmacSha256;
    let password =
        reallyme_crypto::pbkdf2::Pbkdf2Password::from_slice(b"password", prf).expect("password");
    let salt = reallyme_crypto::pbkdf2::Pbkdf2Salt::from_slice(b"salt", prf).expect("salt");
    let iterations = reallyme_crypto::pbkdf2::Pbkdf2Iterations::from_u32_modern(
        reallyme_crypto::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS,
        prf,
    )
    .expect("modern iterations");
    let request = reallyme_crypto::pbkdf2::Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len: 32,
    };

    let operation = reallyme_crypto::operations::kdf::derive_pbkdf2(&request)
        .expect("operation PBKDF2 succeeds");
    let root = reallyme_crypto::pbkdf2::derive_key(&request).expect("root PBKDF2 succeeds");

    assert_eq!(operation.as_bytes(), root.as_bytes());
    assert!(matches!(
        reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw(
            prf,
            b"",
            b"salt",
            reallyme_crypto::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS,
            32,
        ),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        })
    ));
    assert!(matches!(
        reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw(
            prf,
            b"password",
            b"salt",
            reallyme_crypto::pbkdf2::PBKDF2_MAX_ITERATIONS + 1,
            32,
        ),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidParameter,
        })
    ));
    assert!(matches!(
        reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw(
            prf,
            b"password",
            b"salt",
            reallyme_crypto::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS - 1,
            32,
        ),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidParameter,
        })
    ));
    assert!(matches!(
        reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw(
            prf,
            b"password",
            b"salt",
            reallyme_crypto::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS,
            0,
        ),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        })
    ));
}

#[test]
fn hkdf_operation_matches_root_facade() {
    let ikm = reallyme_crypto::hkdf::HkdfInputKeyMaterial::from_slice(b"shared secret material");
    let salt = reallyme_crypto::hkdf::HkdfSalt::from_slice(b"salt");
    let info = reallyme_crypto::hkdf::HkdfInfo::from_slice(b"reallyme/kdf/hkdf");
    let request = reallyme_crypto::hkdf::DeriveRequest {
        suite: reallyme_crypto::hkdf::HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    };

    let operation = reallyme_crypto::operations::kdf::derive_hkdf::<32>(&request)
        .expect("operation HKDF succeeds");
    let root = reallyme_crypto::hkdf::derive::<32>(&request).expect("root HKDF succeeds");

    assert_eq!(operation.as_bytes(), root.as_bytes());
}

#[test]
fn kmac_operation_matches_root_facade() {
    let key = reallyme_crypto::kmac::Kmac256Key::from_slice(&[0x42; 32]).expect("KMAC key");
    let context = b"kdf context";
    let customization = b"kdf customization";

    let operation =
        reallyme_crypto::operations::kdf::derive_kmac256(&key, context, customization, 32)
            .expect("operation KMAC succeeds");
    let root = reallyme_crypto::kmac::derive_kmac256(&key, context, customization, 32)
        .expect("root KMAC succeeds");

    assert_eq!(operation.as_bytes(), root.as_bytes());
}

#[test]
fn jwa_concat_kdf_operation_matches_root_facade() {
    let shared_secret =
        reallyme_crypto::concat_kdf::JwaSharedSecret::from_slice(b"ecdh shared secret")
            .expect("shared secret");
    let algorithm_id =
        reallyme_crypto::concat_kdf::JwaAlgorithmId::from_slice(b"A256GCM").expect("alg id");
    let party_u_info =
        reallyme_crypto::concat_kdf::JwaPartyInfo::from_slice(b"party-u").expect("party u");
    let party_v_info =
        reallyme_crypto::concat_kdf::JwaPartyInfo::from_slice(b"party-v").expect("party v");
    let request = reallyme_crypto::concat_kdf::JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_u_info,
        party_v_info: &party_v_info,
    };

    let operation = reallyme_crypto::operations::kdf::derive_jwa_concat_kdf_sha256::<32>(&request)
        .expect("operation JWA Concat KDF succeeds");
    let root = reallyme_crypto::concat_kdf::derive_jwa_concat_kdf_sha256::<32>(&request)
        .expect("root JWA Concat KDF succeeds");

    assert_eq!(operation.as_bytes(), root.as_bytes());
}

#[test]
fn argon2id_versioned_operation_rejects_unreviewed_profile() {
    assert!(matches!(
        reallyme_crypto::operations::kdf::derive_argon2id_for_version(99, b"password", &[0x11; 16],),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidParameter,
        })
    ));
}
