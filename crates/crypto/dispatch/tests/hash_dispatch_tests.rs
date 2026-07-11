// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
use crypto_core::HashAlgorithm;
use crypto_dispatch::hash_digest;
use crypto_sha2::{digest_sha2_384, digest_sha2_512};
use crypto_sha3::{digest_sha3_224, digest_sha3_384, digest_sha3_512};
use crypto_sha3_256::digest;

#[test]
fn sha2_384_dispatch_matches_known_vector_for_abc() {
    let digest = hash_digest(HashAlgorithm::Sha2_384, b"abc")
        .expect("sha2-384 dispatch hashing should succeed");
    let expected = concat!(
        "cb00753f45a35e8bb5a03d699ac65007",
        "272c32ab0eded1631a8b605a43ff5bed",
        "8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(hex::encode(digest), expected);
}

#[test]
fn sha2_512_dispatch_matches_known_vector_for_abc() {
    let digest = hash_digest(HashAlgorithm::Sha2_512, b"abc")
        .expect("sha2-512 dispatch hashing should succeed");
    let expected = concat!(
        "ddaf35a193617abacc417349ae204131",
        "12e6fa4e89a97ea20a9eeee64b55d39a",
        "2192992a274fc1a836ba3c23a3feebbd",
        "454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(hex::encode(digest), expected);
}

#[test]
fn sha2_wide_dispatch_matches_primitive_wrappers() {
    let message = b"dispatch wide sha2";
    let sha384 = hash_digest(HashAlgorithm::Sha2_384, message)
        .expect("sha2-384 dispatch hashing should succeed");
    let sha512 = hash_digest(HashAlgorithm::Sha2_512, message)
        .expect("sha2-512 dispatch hashing should succeed");

    assert_eq!(
        digest_sha2_384(message).as_bytes().as_slice(),
        sha384.as_slice()
    );
    assert_eq!(
        digest_sha2_512(message).as_bytes().as_slice(),
        sha512.as_slice()
    );
}

#[test]
fn sha3_256_dispatch_matches_known_vector_for_abc() {
    let digest = hash_digest(HashAlgorithm::Sha3_256, b"abc")
        .expect("sha3-256 dispatch hashing should succeed");
    let expected = "3a985da74fe225b2045c172d6bd390bd\
                    855f086e3e9d525b46bfe24511431532";
    assert_eq!(hex::encode(digest), expected);
}

#[test]
fn sha3_224_dispatch_matches_known_vector_for_abc() {
    let digest = hash_digest(HashAlgorithm::Sha3_224, b"abc")
        .expect("sha3-224 dispatch hashing should succeed");
    let expected = "e642824c3f8cf24ad09234ee7d3c766f\
                    c9a3a5168d0c94ad73b46fdf";
    assert_eq!(hex::encode(digest), expected);
}

#[test]
fn sha3_384_dispatch_matches_known_vector_for_abc() {
    let digest = hash_digest(HashAlgorithm::Sha3_384, b"abc")
        .expect("sha3-384 dispatch hashing should succeed");
    let expected = concat!(
        "ec01498288516fc926459f58e2c6ad8d",
        "f9b473cb0fc08c2596da7cf0e49be4b2",
        "98d88cea927ac7f539f1edf228376d25"
    );
    assert_eq!(hex::encode(digest), expected);
}

#[test]
fn sha3_512_dispatch_matches_known_vector_for_abc() {
    let digest = hash_digest(HashAlgorithm::Sha3_512, b"abc")
        .expect("sha3-512 dispatch hashing should succeed");
    let expected = concat!(
        "b751850b1a57168a5693cd924b6b096e",
        "08f621827444f70d884f5d0240d2712e",
        "10e116e9192af3c91a7ec57647e39340",
        "57340b4cf408d5a56592f8274eec53f0"
    );
    assert_eq!(hex::encode(digest), expected);
}

#[test]
fn sha3_dispatch_is_deterministic() {
    for algorithm in [
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
    ] {
        let first =
            hash_digest(algorithm, b"dispatch-sha3").expect("sha3 dispatch hashing should succeed");
        let second =
            hash_digest(algorithm, b"dispatch-sha3").expect("sha3 dispatch hashing should succeed");
        assert_eq!(first, second);
    }
}

#[test]
fn sha3_wide_dispatch_matches_primitive_wrappers() {
    let message = b"dispatch wide sha3";
    let sha3_224 = hash_digest(HashAlgorithm::Sha3_224, message)
        .expect("sha3-224 dispatch hashing should succeed");
    let sha3_384 = hash_digest(HashAlgorithm::Sha3_384, message)
        .expect("sha3-384 dispatch hashing should succeed");
    let sha3_512 = hash_digest(HashAlgorithm::Sha3_512, message)
        .expect("sha3-512 dispatch hashing should succeed");

    assert_eq!(
        digest_sha3_224(message).as_bytes().as_slice(),
        sha3_224.as_slice()
    );
    assert_eq!(
        digest_sha3_384(message).as_bytes().as_slice(),
        sha3_384.as_slice()
    );
    assert_eq!(
        digest_sha3_512(message).as_bytes().as_slice(),
        sha3_512.as_slice()
    );
}

#[test]
fn sha3_256_dispatch_matches_regression_vectors() {
    let vectors = [
        (
            b"".as_slice(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        ),
        (
            b"The quick brown fox jumps over the lazy dog".as_slice(),
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
        ),
        (
            b"The quick brown fox jumps over the lazy dog.".as_slice(),
            "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
        ),
    ];

    for (message, digest_hex) in vectors {
        let dispatched =
            hash_digest(HashAlgorithm::Sha3_256, message).expect("dispatch hashing must succeed");
        let primitive = digest(message);
        assert_eq!(hex::encode(&dispatched), digest_hex);
        assert_eq!(primitive.as_bytes().as_slice(), dispatched.as_slice());
    }
}
