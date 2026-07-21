// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "constant-time",
    feature = "dispatch",
    feature = "sha2",
    feature = "sha3"
))]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Operation-owner tests for hash and constant-time routes.

use crypto_core::HashAlgorithm;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};

#[test]
fn hash_operation_matches_canonical_cross_lane_vectors() {
    let message = b"ReallyMe SHA conformance vector";
    let cases = [
        (
            HashAlgorithm::Sha2_256,
            "f501c495424ebf5cc85aafe5ae67ab7bd53ddc7551bba470ce6ab2a3ed11c267",
        ),
        (
            HashAlgorithm::Sha2_384,
            "bc0bd7ab266a535dbbee85a3c752e26ffd8dcd279a8bf3e5796de71ad16dff3f99537b6818e68a6c526f55022563973c",
        ),
        (
            HashAlgorithm::Sha2_512,
            "85c8d3bcf65c82e40f7f95d7110f4a6345d9263f8d276f43ec367833cebcea8928e86cbd9addff6a73e986e2257fa6569b1acb73bae1ef531d37db9524ec149f",
        ),
        (
            HashAlgorithm::Sha3_224,
            "1a73161b8cd6eaea2d9012c4e2f824c3391286deb12b95e8d15a6ebd",
        ),
        (
            HashAlgorithm::Sha3_256,
            "e72310bf14eb7ebce18ee856920f52d775e5181277e0300861031fcafedb911a",
        ),
        (
            HashAlgorithm::Sha3_384,
            "958127d45f72c08ee59a0b4de3c44a68577b414965cda08ffb84b52a8c47eb577885448a08cb200cc33f44227e33a03f",
        ),
        (
            HashAlgorithm::Sha3_512,
            "bbc0863f6fb1ae5107e04e79f29d71ca567aedc864e16348fe3cacbb307e33a28d905da0fcc32e3f1de17442b576acddbe79096862d08c2460948f8773d2f19c",
        ),
    ];

    for (algorithm, expected_hex) in cases {
        let actual = reallyme_crypto::operations::hash::digest(algorithm, message)
            .expect("hash operation succeeds");

        assert_eq!(
            encode_hex(actual.as_slice()),
            expected_hex,
            "canonical vector mismatch for {algorithm:?}"
        );
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    let capacity = bytes
        .len()
        .checked_mul(2)
        .expect("test digest hex capacity fits usize");
    let mut output = String::with_capacity(capacity);
    for byte in bytes {
        output.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[test]
fn hash_operation_matches_root_dispatch_facade_for_supported_algorithms() {
    let input = b"reallyme crypto hash parity";
    let cases = [
        (HashAlgorithm::Sha2_256, 32usize),
        (HashAlgorithm::Sha2_384, 48usize),
        (HashAlgorithm::Sha2_512, 64usize),
        (HashAlgorithm::Sha3_224, 28usize),
        (HashAlgorithm::Sha3_256, 32usize),
        (HashAlgorithm::Sha3_384, 48usize),
        (HashAlgorithm::Sha3_512, 64usize),
    ];

    for (algorithm, expected_len) in cases {
        let operation_digest =
            reallyme_crypto::operations::hash::digest(algorithm, input).expect("hash succeeds");
        let facade_digest =
            reallyme_crypto::dispatch::hash_digest(algorithm, input).expect("facade succeeds");

        assert_eq!(operation_digest.len(), expected_len);
        assert_eq!(operation_digest, facade_digest);
    }
}

#[test]
fn hash_operation_matches_root_primitive_facades() {
    let input = b"reallyme crypto root hash facade parity";

    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha2_256, input)
            .expect("sha2-256 operation succeeds"),
        reallyme_crypto::sha2::digest(input).into_bytes().to_vec()
    );
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha2_384, input)
            .expect("sha2-384 operation succeeds"),
        reallyme_crypto::sha2::digest_sha2_384(input)
            .into_bytes()
            .to_vec()
    );
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha2_512, input)
            .expect("sha2-512 operation succeeds"),
        reallyme_crypto::sha2::digest_sha2_512(input)
            .into_bytes()
            .to_vec()
    );
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha3_224, input)
            .expect("sha3-224 operation succeeds"),
        reallyme_crypto::sha3::digest_sha3_224(input)
            .into_bytes()
            .to_vec()
    );
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha3_256, input)
            .expect("sha3-256 operation succeeds"),
        reallyme_crypto::sha3::digest(input).into_bytes().to_vec()
    );
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha3_384, input)
            .expect("sha3-384 operation succeeds"),
        reallyme_crypto::sha3::digest_sha3_384(input)
            .into_bytes()
            .to_vec()
    );
    assert_eq!(
        reallyme_crypto::operations::hash::digest(HashAlgorithm::Sha3_512, input)
            .expect("sha3-512 operation succeeds"),
        reallyme_crypto::sha3::digest_sha3_512(input)
            .into_bytes()
            .to_vec()
    );
}

#[test]
fn constant_time_operation_compares_equal_length_inputs() {
    let left = b"same public length";
    let equal = b"same public length";
    let different = b"same public lengti";
    let shorter = b"shorter";

    assert!(reallyme_crypto::operations::constant_time::equal(
        left, equal
    ));
    assert!(!reallyme_crypto::operations::constant_time::equal(
        left, different
    ));
    assert!(!reallyme_crypto::operations::constant_time::equal(
        left, shorter
    ));

    let fixed_left = *b"fixed-size-array";
    let fixed_equal = *b"fixed-size-array";
    let fixed_different = *b"fixed-size-arrby";
    assert!(reallyme_crypto::operations::constant_time::equal_fixed(
        &fixed_left,
        &fixed_equal,
    ));
    assert!(!reallyme_crypto::operations::constant_time::equal_fixed(
        &fixed_left,
        &fixed_different,
    ));
}

#[test]
fn constant_time_require_equal_preserves_stable_failure_reasons() {
    let left = b"same public length";
    let different = b"same public lengti";
    let shorter = b"shorter";

    assert_eq!(
        reallyme_crypto::operations::constant_time::require_equal(left, different),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        })
    );
    assert_eq!(
        reallyme_crypto::operations::constant_time::require_equal(left, shorter),
        Err(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        })
    );
}
