// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA and SLH-DSA signature operation tests.

#![allow(clippy::expect_used, clippy::panic)]

use crypto_core::Algorithm;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};
use zeroize::Zeroizing;

const MESSAGE: &[u8] = b"post-quantum signature operation";

#[test]
fn ml_dsa_operations_match_primitive_parameter_sets_and_reject_tampering() {
    ml_dsa_round_trip(
        Algorithm::MlDsa44,
        &[0x44; crypto_ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN],
        crypto_ml_dsa_44::generate_ml_dsa_44_keypair_from_seed,
        crypto_ml_dsa_44::sign_ml_dsa_44,
        crypto_ml_dsa_44::verify_ml_dsa_44,
    );
    ml_dsa_round_trip(
        Algorithm::MlDsa65,
        &[0x65; crypto_ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN],
        crypto_ml_dsa_65::generate_ml_dsa_65_keypair_from_seed,
        crypto_ml_dsa_65::sign_ml_dsa_65,
        crypto_ml_dsa_65::verify_ml_dsa_65,
    );
    ml_dsa_round_trip(
        Algorithm::MlDsa87,
        &[0x87; crypto_ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN],
        crypto_ml_dsa_87::generate_ml_dsa_87_keypair_from_seed,
        crypto_ml_dsa_87::sign_ml_dsa_87,
        crypto_ml_dsa_87::verify_ml_dsa_87,
    );
}

#[test]
fn slh_dsa_operation_matches_primitive_and_rejects_tampering() {
    let seed_material = slh_seed_material();
    let primitive_keypair = crypto_slh_dsa::derive_slh_dsa_sha2_128s_keypair(
        &seed_material[..16],
        &seed_material[16..32],
        &seed_material[32..48],
    )
    .expect("primitive derives SLH-DSA keypair");
    let operation_keypair = reallyme_crypto::operations::signature::derive_key_pair(
        Algorithm::SlhDsaSha2_128s,
        &seed_material,
    )
    .expect("operation derives SLH-DSA keypair");
    assert_eq!(operation_keypair.public_key, primitive_keypair.0);
    assert_eq!(
        operation_keypair.secret_key.as_slice(),
        primitive_keypair.1.as_slice()
    );

    let operation_signature = reallyme_crypto::operations::signature::sign(
        Algorithm::SlhDsaSha2_128s,
        &operation_keypair.secret_key,
        MESSAGE,
    )
    .expect("operation signs SLH-DSA");
    crypto_slh_dsa::verify_slh_dsa_sha2_128s(
        &operation_keypair.public_key,
        MESSAGE,
        &operation_signature,
    )
    .expect("primitive verifies operation SLH-DSA signature");

    let mut tampered = operation_signature;
    tampered[0] ^= 0x01;
    let error = reallyme_crypto::operations::signature::verify(
        Algorithm::SlhDsaSha2_128s,
        &operation_keypair.public_key,
        MESSAGE,
        &tampered,
    )
    .expect_err("tampered SLH-DSA signature fails");
    assert_eq!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed
        }
    );
}

#[test]
fn slh_dsa_derivation_rejects_partial_seed_material() {
    let result = reallyme_crypto::operations::signature::derive_key_pair(
        Algorithm::SlhDsaSha2_128s,
        &[0x11; 47],
    );
    let error = match result {
        Ok(_) => {
            panic!("SLH-DSA derivation accepted partial seed material");
        }
        Err(error) => error,
    };
    assert_eq!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey
        }
    );
}

fn ml_dsa_round_trip<G, S, V>(
    algorithm: Algorithm,
    seed: &[u8; 32],
    primitive_keypair: G,
    primitive_sign: S,
    primitive_verify: V,
) where
    G: Fn(&[u8; 32]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), crypto_core::CryptoError>,
    S: Fn(&[u8], &[u8]) -> Result<Vec<u8>, crypto_core::CryptoError>,
    V: Fn(&[u8], &[u8], &[u8]) -> Result<(), crypto_core::CryptoError>,
{
    let primitive_keypair = primitive_keypair(seed).expect("primitive derives ML-DSA keypair");
    let operation_keypair =
        reallyme_crypto::operations::signature::derive_key_pair(algorithm, seed)
            .expect("operation derives ML-DSA keypair");
    assert_eq!(operation_keypair.public_key, primitive_keypair.0);
    assert_eq!(
        operation_keypair.secret_key.as_slice(),
        primitive_keypair.1.as_slice()
    );

    let primitive_signature = primitive_sign(seed, MESSAGE).expect("primitive signs ML-DSA");
    let operation_signature =
        reallyme_crypto::operations::signature::sign(algorithm, seed, MESSAGE)
            .expect("operation signs ML-DSA");
    assert_eq!(operation_signature, primitive_signature);
    primitive_verify(&operation_keypair.public_key, MESSAGE, &operation_signature)
        .expect("primitive verifies operation ML-DSA signature");

    let mut tampered = operation_signature;
    tampered[0] ^= 0x01;
    let error = reallyme_crypto::operations::signature::verify(
        algorithm,
        &operation_keypair.public_key,
        MESSAGE,
        &tampered,
    )
    .expect_err("tampered ML-DSA signature fails");
    assert_eq!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed
        }
    );
}

fn slh_seed_material() -> Zeroizing<Vec<u8>> {
    let mut seed_material = Zeroizing::new(Vec::with_capacity(48));
    seed_material.extend_from_slice(&[0x11; 16]);
    seed_material.extend_from_slice(&[0x22; 16]);
    seed_material.extend_from_slice(&[0x33; 16]);
    seed_material
}
