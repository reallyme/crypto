// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-boundary parity and failure tests for the MAC C ABI adapters.

#![allow(unsafe_code)]
#![allow(clippy::expect_used)]

use crypto_core::MacAlgorithm;
use crypto_ffi::hmac;
use crypto_ffi::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_INVALID_ARGUMENT, CRYPTO_OK,
};
use reallyme_crypto::operations::OperationError;

type AuthenticateFunction =
    unsafe extern "C" fn(u32, *const u8, usize, *const u8, usize, *mut u8, usize) -> CryptoStatus;

type VerifyFunction =
    unsafe extern "C" fn(u32, *const u8, usize, *const u8, usize, *const u8, usize) -> CryptoStatus;

struct MacFfiCase {
    algorithm: MacAlgorithm,
    suite: u32,
    tag_length: usize,
}

const MAC_FFI_CASES: &[MacFfiCase] = &[
    MacFfiCase {
        algorithm: MacAlgorithm::HmacSha256,
        suite: hmac::HMAC_SUITE_SHA256,
        tag_length: hmac::HMAC_SHA256_TAG_LEN,
    },
    MacFfiCase {
        algorithm: MacAlgorithm::HmacSha512,
        suite: hmac::HMAC_SUITE_SHA512,
        tag_length: hmac::HMAC_SHA512_TAG_LEN,
    },
];

const AUTHENTICATE: AuthenticateFunction = hmac::rm_crypto_hmac_authenticate;
const VERIFY: VerifyFunction = hmac::rm_crypto_hmac_verify;

#[test]
fn c_hmac_adapters_match_the_operation_owner_and_fail_closed() -> Result<(), OperationError> {
    let key = [0x42u8; 32];
    let message = b"ReallyMe MAC C ABI parity";

    for case in MAC_FFI_CASES {
        let expected =
            reallyme_crypto::operations::mac::authenticate(case.algorithm, &key, message)?;
        let mut actual = vec![0u8; case.tag_length];
        let status = unsafe {
            AUTHENTICATE(
                case.suite,
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                actual.as_mut_ptr(),
                actual.len(),
            )
        };

        assert_eq!(status, CRYPTO_OK);
        assert_eq!(actual, expected);

        let short_tag_length = case
            .tag_length
            .checked_sub(1)
            .expect("a supported HMAC tag length is non-zero");
        let status = unsafe {
            VERIFY(
                case.suite,
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                actual.as_ptr(),
                actual.len(),
            )
        };
        assert_eq!(status, CRYPTO_OK);

        let first = actual
            .first_mut()
            .expect("a supported HMAC tag is non-empty");
        *first ^= 0x01;
        let status = unsafe {
            VERIFY(
                case.suite,
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                actual.as_ptr(),
                actual.len(),
            )
        };
        assert_eq!(status, CRYPTO_AUTHENTICATION_FAILED);

        let status = unsafe {
            VERIFY(
                case.suite,
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                actual.as_ptr(),
                short_tag_length,
            )
        };
        assert_eq!(status, CRYPTO_INVALID_ARGUMENT);
    }

    Ok(())
}
