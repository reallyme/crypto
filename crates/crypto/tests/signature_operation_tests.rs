// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Signature operation coverage from Ed25519 through RSA verification.

#![allow(clippy::expect_used)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crypto_core::Algorithm;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};
use reallyme_crypto::rsa::{RsaHash, RsaPssParams, RsaPublicKeyDerEncoding};

const MESSAGE: &[u8] = b"signature operation parity";
const RSA_MESSAGE: &str = "UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg";
const RSA_PUBLIC_KEY_DER: &str = "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB";
const RSA_PKCS1V15_SHA256_SIGNATURE: &str = "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw";
const RSA_PSS_SHA256_SIGNATURE: &str = "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw";
const RSA_PSS_SHA256_SALT_LEN: usize = 32;
const BIP340_SECRET_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
const BIP340_MESSAGE32: [u8; 32] = [0; 32];
const BIP340_AUX_RAND32: [u8; 32] = [0; 32];
const BIP340_PUBLIC_KEY: [u8; 32] = [
    0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
    0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9,
];
const BIP340_SIGNATURE: [u8; 64] = [
    0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10, 0x36,
    0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca, 0x82, 0x15,
    0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38, 0x2d, 0x2c, 0xe5,
    0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d, 0x31, 0x05, 0x36, 0xc0,
];

#[test]
fn ed25519_operation_matches_primitive_and_rejects_expanded_keys() {
    let seed = [0x42; 32];
    let primitive_keypair = crypto_ed25519::generate_ed25519_keypair_from_seed(&seed);
    let operation_keypair =
        reallyme_crypto::operations::signature::derive_key_pair(Algorithm::Ed25519, &seed)
            .expect("operation derives Ed25519 keypair");
    assert_eq!(operation_keypair.public_key, primitive_keypair.0);

    let primitive_signature =
        crypto_ed25519::sign_ed25519(&seed, MESSAGE).expect("primitive signs");
    let operation_signature =
        reallyme_crypto::operations::signature::sign(Algorithm::Ed25519, &seed, MESSAGE)
            .expect("operation signs");
    assert_eq!(operation_signature, primitive_signature);
    reallyme_crypto::operations::signature::verify(
        Algorithm::Ed25519,
        &operation_keypair.public_key,
        MESSAGE,
        &operation_signature,
    )
    .expect("operation verifies");

    let mut expanded = Vec::with_capacity(64);
    expanded.extend_from_slice(&seed);
    expanded.extend_from_slice(&operation_keypair.public_key);
    let error =
        reallyme_crypto::operations::signature::sign(Algorithm::Ed25519, &expanded, MESSAGE)
            .expect_err("expanded Ed25519 keys are rejected");
    assert_eq!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey
        }
    );
}

#[test]
fn nist_ecdsa_operations_match_primitive_verifiers() {
    p256_round_trip();
    p384_round_trip();
    p521_round_trip();
}

#[test]
fn secp256k1_ecdsa_operation_matches_primitive_and_rejects_tampering() {
    let secret = [0x05; 32];
    let (public_key, _) = crypto_secp256k1::generate_secp256k1_keypair_from_secret_key(&secret)
        .expect("valid secp256k1 scalar");
    let operation_signature =
        reallyme_crypto::operations::signature::sign(Algorithm::Secp256k1, &secret, MESSAGE)
            .expect("operation signs");
    let primitive_signature =
        crypto_secp256k1::sign_secp256k1(&secret, MESSAGE).expect("primitive signs");
    assert_eq!(operation_signature, primitive_signature);
    crypto_secp256k1::verify_secp256k1(&operation_signature, MESSAGE, &public_key)
        .expect("primitive verifies operation signature");

    let mut tampered = operation_signature;
    tampered[0] ^= 0x01;
    let error = reallyme_crypto::operations::signature::verify(
        Algorithm::Secp256k1,
        &public_key,
        MESSAGE,
        &tampered,
    )
    .expect_err("tampered signature fails");
    assert_eq!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed
        }
    );
}

#[test]
fn bip340_schnorr_operation_matches_official_vector_and_rejects_invalids() {
    let public_key =
        reallyme_crypto::operations::signature::derive_bip340_public_key(&BIP340_SECRET_KEY)
            .expect("operation derives BIP-340 public key");
    assert_eq!(public_key, BIP340_PUBLIC_KEY);

    let signature = reallyme_crypto::operations::signature::sign_bip340(
        &BIP340_SECRET_KEY,
        &BIP340_MESSAGE32,
        &BIP340_AUX_RAND32,
    )
    .expect("operation signs BIP-340");
    assert_eq!(signature, BIP340_SIGNATURE);
    reallyme_crypto::operations::signature::verify_bip340(
        &signature,
        &BIP340_MESSAGE32,
        &public_key,
    )
    .expect("operation verifies BIP-340");

    let short_message_error = reallyme_crypto::operations::signature::sign_bip340(
        &BIP340_SECRET_KEY,
        &BIP340_MESSAGE32[1..],
        &BIP340_AUX_RAND32,
    )
    .expect_err("short BIP-340 messages are rejected");
    assert_eq!(
        short_message_error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength
        }
    );

    let mut tampered = signature;
    tampered[0] ^= 0x01;
    let tampered_error = reallyme_crypto::operations::signature::verify_bip340(
        &tampered,
        &BIP340_MESSAGE32,
        &public_key,
    )
    .expect_err("tampered BIP-340 signatures are rejected");
    assert_eq!(
        tampered_error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed
        }
    );
}

#[test]
fn rsa_operation_verifies_pkcs1v15_and_pss_vectors() {
    let public_key = decode_base64url(RSA_PUBLIC_KEY_DER);
    let message = decode_base64url(RSA_MESSAGE);
    let pkcs1_signature = decode_base64url(RSA_PKCS1V15_SHA256_SIGNATURE);
    reallyme_crypto::operations::signature::verify_rsa_pkcs1v15(
        &public_key,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaHash::Sha256,
        &message,
        &pkcs1_signature,
    )
    .expect("operation verifies RSA PKCS#1 v1.5");

    let pss_signature = decode_base64url(RSA_PSS_SHA256_SIGNATURE);
    reallyme_crypto::operations::signature::verify_rsa_pss(
        &public_key,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaPssParams {
            message_hash: RsaHash::Sha256,
            mgf1_hash: RsaHash::Sha256,
            salt_len: RSA_PSS_SHA256_SALT_LEN,
        },
        &message,
        &pss_signature,
    )
    .expect("operation verifies RSA-PSS");
}

#[test]
fn rsa_operation_rejects_invalid_key_and_tampered_signature() {
    let public_key = decode_base64url(RSA_PUBLIC_KEY_DER);
    let message = decode_base64url(RSA_MESSAGE);
    let mut signature = decode_base64url(RSA_PKCS1V15_SHA256_SIGNATURE);

    signature[0] ^= 0x01;
    let tampered = reallyme_crypto::operations::signature::verify_rsa_pkcs1v15(
        &public_key,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaHash::Sha256,
        &message,
        &signature,
    )
    .expect_err("tampered RSA signature fails");
    assert_eq!(
        tampered,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed
        }
    );

    let invalid_key = reallyme_crypto::operations::signature::verify_rsa_pkcs1v15(
        &[0x30, 0x00],
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaHash::Sha256,
        &message,
        &signature,
    )
    .expect_err("malformed RSA public key fails");
    assert_eq!(
        invalid_key,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey
        }
    );
}

fn p256_round_trip() {
    let secret = [0x01; 32];
    let (public_key, _) =
        crypto_p256::generate_p256_keypair_from_secret_key(&secret).expect("valid P-256 scalar");
    let signature = reallyme_crypto::operations::signature::sign(Algorithm::P256, &secret, MESSAGE)
        .expect("operation signs P-256");
    crypto_p256::verify_p256_der_prehash(&signature, MESSAGE, &public_key)
        .expect("primitive verifies P-256");
}

fn p384_round_trip() {
    let secret = [0x01; 48];
    let (public_key, _) =
        crypto_p384::generate_p384_keypair_from_secret_key(&secret).expect("valid P-384 scalar");
    let signature = reallyme_crypto::operations::signature::sign(Algorithm::P384, &secret, MESSAGE)
        .expect("operation signs P-384");
    crypto_p384::verify_p384_der_prehash(&signature, MESSAGE, &public_key)
        .expect("primitive verifies P-384");
}

fn p521_round_trip() {
    let secret = [0x01; 66];
    let (public_key, _) =
        crypto_p521::generate_p521_keypair_from_secret_key(&secret).expect("valid P-521 scalar");
    let signature = reallyme_crypto::operations::signature::sign(Algorithm::P521, &secret, MESSAGE)
        .expect("operation signs P-521");
    crypto_p521::verify_p521_der_prehash(&signature, MESSAGE, &public_key)
        .expect("primitive verifies P-521");
}

fn decode_base64url(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("RSA vector base64url decodes")
}
