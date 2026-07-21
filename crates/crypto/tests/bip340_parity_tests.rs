// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! BIP-340 semantic-owner, root-facade, and negative parity coverage.

#![cfg(feature = "secp256k1")]
#![allow(clippy::expect_used)]

use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};

const SECRET_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
const MESSAGE32: [u8; 32] = [0; 32];
const AUX_RAND32: [u8; 32] = [0; 32];
const PUBLIC_KEY: [u8; 32] = [
    0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
    0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9,
];
const SIGNATURE: [u8; 64] = [
    0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10, 0x36,
    0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca, 0x82, 0x15,
    0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38, 0x2d, 0x2c, 0xe5,
    0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d, 0x31, 0x05, 0x36, 0xc0,
];

#[test]
fn bip340_key_generation_and_derivation_preserve_xonly_key_shape() {
    let generated = reallyme_crypto::operations::signature::generate_bip340_key_pair()
        .expect("BIP-340 key generation succeeds");
    assert_eq!(generated.public_key.len(), 32);
    assert_eq!(generated.secret_key.len(), 32);
    let generated_public =
        reallyme_crypto::operations::signature::derive_bip340_public_key(&generated.secret_key)
            .expect("generated secret scalar derives");
    assert_eq!(generated.public_key, generated_public);

    let derived = reallyme_crypto::operations::signature::derive_bip340_key_pair(&SECRET_KEY)
        .expect("official scalar derives");
    assert_eq!(derived.public_key, PUBLIC_KEY);
    assert_eq!(derived.secret_key.as_slice(), SECRET_KEY);

    let (root_public, root_secret) =
        reallyme_crypto::secp256k1::generate_bip340_schnorr_keypair_from_secret_key(&SECRET_KEY)
            .expect("root facade derives BIP-340 keypair");
    assert_eq!(root_public, PUBLIC_KEY);
    assert_eq!(root_secret.as_slice(), SECRET_KEY);
}

#[test]
fn bip340_sign_and_verify_match_the_official_vector_across_public_routes() {
    let operation_signature =
        reallyme_crypto::operations::signature::sign_bip340(&SECRET_KEY, &MESSAGE32, &AUX_RAND32)
            .expect("operation owner signs official vector");
    assert_eq!(operation_signature, SIGNATURE);

    let root_signature =
        reallyme_crypto::secp256k1::sign_bip340_schnorr(&SECRET_KEY, &MESSAGE32, &AUX_RAND32)
            .expect("root facade signs official vector");
    assert_eq!(root_signature, operation_signature);

    reallyme_crypto::operations::signature::verify_bip340(
        &operation_signature,
        &MESSAGE32,
        &PUBLIC_KEY,
    )
    .expect("operation owner verifies official vector");
    reallyme_crypto::secp256k1::verify_bip340_schnorr(&root_signature, &MESSAGE32, &PUBLIC_KEY)
        .expect("root facade verifies official vector");
}

#[test]
fn bip340_rejects_invalid_scalars_lengths_keys_and_tampering_with_typed_errors() {
    let invalid_scalar = reallyme_crypto::operations::signature::derive_bip340_key_pair(&[0; 32]);
    assert!(invalid_scalar.is_err());
    assert_eq!(
        invalid_scalar.err(),
        Some(primitive_error(PrimitiveErrorReason::InvalidKey))
    );
    assert_eq!(
        reallyme_crypto::operations::signature::sign_bip340(
            &SECRET_KEY,
            &MESSAGE32[1..],
            &AUX_RAND32,
        )
        .expect_err("short message is invalid"),
        primitive_error(PrimitiveErrorReason::InvalidLength)
    );
    assert_eq!(
        reallyme_crypto::operations::signature::sign_bip340(
            &SECRET_KEY,
            &MESSAGE32,
            &AUX_RAND32[1..],
        )
        .expect_err("short auxiliary randomness is invalid"),
        primitive_error(PrimitiveErrorReason::InvalidLength)
    );

    let mut tampered = SIGNATURE;
    tampered[0] ^= 1;
    assert_eq!(
        reallyme_crypto::operations::signature::verify_bip340(&tampered, &MESSAGE32, &PUBLIC_KEY,)
            .expect_err("tampered signature is invalid"),
        primitive_error(PrimitiveErrorReason::VerificationFailed)
    );
    assert_eq!(
        reallyme_crypto::operations::signature::verify_bip340(&SIGNATURE, &MESSAGE32, &[0xff; 32],)
            .expect_err("non-curve x-only key is invalid"),
        primitive_error(PrimitiveErrorReason::InvalidKey)
    );
}

fn primitive_error(reason: PrimitiveErrorReason) -> OperationError {
    OperationError::Primitive { reason }
}
