// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-boundary parity tests for the hash and constant-time C ABI adapters.

#![allow(unsafe_code)]

use crypto_core::HashAlgorithm;
use crypto_ffi::status::{CryptoStatus, CRYPTO_OK};
use crypto_ffi::{constant_time, sha2, sha2_256, sha3, sha3_256};
use reallyme_crypto::operations::OperationError;

type HashFunction = unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> CryptoStatus;

#[test]
fn c_hash_adapters_match_the_operation_owner() -> Result<(), OperationError> {
    let message = b"ReallyMe hash and constant-time C ABI parity";
    let cases: [(HashAlgorithm, usize, HashFunction); 7] = [
        (
            HashAlgorithm::Sha2_256,
            sha2_256::SHA2_256_DIGEST_LEN,
            sha2_256::rm_crypto_sha2_256_digest,
        ),
        (
            HashAlgorithm::Sha2_384,
            sha2::SHA2_384_DIGEST_LEN,
            sha2::rm_crypto_sha2_384_digest,
        ),
        (
            HashAlgorithm::Sha2_512,
            sha2::SHA2_512_DIGEST_LEN,
            sha2::rm_crypto_sha2_512_digest,
        ),
        (
            HashAlgorithm::Sha3_224,
            sha3::SHA3_224_DIGEST_LEN,
            sha3::rm_crypto_sha3_224_digest,
        ),
        (
            HashAlgorithm::Sha3_256,
            sha3_256::SHA3_256_DIGEST_LEN,
            sha3_256::rm_crypto_sha3_256_digest,
        ),
        (
            HashAlgorithm::Sha3_384,
            sha3::SHA3_384_DIGEST_LEN,
            sha3::rm_crypto_sha3_384_digest,
        ),
        (
            HashAlgorithm::Sha3_512,
            sha3::SHA3_512_DIGEST_LEN,
            sha3::rm_crypto_sha3_512_digest,
        ),
    ];

    for (algorithm, digest_length, function) in cases {
        let expected = reallyme_crypto::operations::hash::digest(algorithm, message)?;
        let mut actual = vec![0u8; digest_length];
        let status = unsafe {
            function(
                message.as_ptr(),
                message.len(),
                actual.as_mut_ptr(),
                actual.len(),
            )
        };

        assert_eq!(status, CRYPTO_OK, "C hash adapter failed for {algorithm:?}");
        assert_eq!(actual, expected, "C hash parity failed for {algorithm:?}");
    }

    Ok(())
}

#[test]
fn c_constant_time_adapter_matches_the_operation_owner() {
    let cases: [(&[u8], &[u8]); 4] = [
        (b"", b""),
        (b"equal", b"equal"),
        (b"equal", b"other"),
        (b"different lengths", b"short"),
    ];

    for (left, right) in cases {
        let expected = reallyme_crypto::operations::constant_time::equal(left, right);
        let mut actual = 0i32;
        let status = unsafe {
            constant_time::rm_crypto_constant_time_equal(
                left.as_ptr(),
                left.len(),
                right.as_ptr(),
                right.len(),
                &mut actual,
            )
        };

        assert_eq!(status, CRYPTO_OK);
        assert_eq!(actual, i32::from(expected));
    }
}
