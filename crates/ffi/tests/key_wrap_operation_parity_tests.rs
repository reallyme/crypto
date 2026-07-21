// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(unsafe_code)]

//! C ABI parity tests for AES-KW routes backed by the operation owner.

use core::ptr::NonNull;
use crypto_core::KeyWrapAlgorithm;
use crypto_ffi::{aes_kw, status};

type WrapFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> status::CryptoStatus;

type UnwrapFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> status::CryptoStatus;

struct KeyWrapFfiCase {
    algorithm: KeyWrapAlgorithm,
    kek_len: usize,
    wrap: WrapFn,
    unwrap: UnwrapFn,
}

const KEY_WRAP_FFI_CASES: &[KeyWrapFfiCase] = &[
    KeyWrapFfiCase {
        algorithm: KeyWrapAlgorithm::Aes128Kw,
        kek_len: aes_kw::AES128_KW_KEK_LEN,
        wrap: aes_kw::rm_crypto_aes128_kw_wrap_key,
        unwrap: aes_kw::rm_crypto_aes128_kw_unwrap_key,
    },
    KeyWrapFfiCase {
        algorithm: KeyWrapAlgorithm::Aes192Kw,
        kek_len: aes_kw::AES192_KW_KEK_LEN,
        wrap: aes_kw::rm_crypto_aes192_kw_wrap_key,
        unwrap: aes_kw::rm_crypto_aes192_kw_unwrap_key,
    },
    KeyWrapFfiCase {
        algorithm: KeyWrapAlgorithm::Aes256Kw,
        kek_len: aes_kw::AES256_KW_KEK_LEN,
        wrap: aes_kw::rm_crypto_aes256_kw_wrap_key,
        unwrap: aes_kw::rm_crypto_aes256_kw_unwrap_key,
    },
];

#[test]
fn c_abi_key_wrap_routes_match_operation_owner_and_reject_tampering() {
    let key_data = bytes(32, 0xa0);

    for case in KEY_WRAP_FFI_CASES {
        let kek = bytes(case.kek_len, 0x51);
        let expected_wrapped =
            reallyme_crypto::operations::key_wrap::wrap_key(case.algorithm, &kek, &key_data)
                .expect("operation wrap succeeds");
        let mut wrapped = vec![0u8; expected_wrapped.len()];
        let mut wrapped_len = 0usize;

        let wrap_status = unsafe {
            (case.wrap)(
                kek.as_ptr(),
                kek.len(),
                key_data.as_ptr(),
                key_data.len(),
                wrapped.as_mut_ptr(),
                wrapped.len(),
                &mut wrapped_len,
            )
        };
        assert_eq!(wrap_status, status::CRYPTO_OK);
        assert_eq!(wrapped_len, expected_wrapped.len());
        assert_eq!(wrapped, expected_wrapped.as_bytes());

        let mut unwrapped = vec![0u8; key_data.len()];
        let mut unwrapped_len = 0usize;
        let unwrap_status = unsafe {
            (case.unwrap)(
                kek.as_ptr(),
                kek.len(),
                wrapped.as_ptr(),
                wrapped_len,
                unwrapped.as_mut_ptr(),
                unwrapped.len(),
                &mut unwrapped_len,
            )
        };
        assert_eq!(unwrap_status, status::CRYPTO_OK);
        assert_eq!(unwrapped_len, key_data.len());
        assert_eq!(unwrapped, key_data);

        let first = wrapped.first_mut().expect("wrapped key is not empty");
        *first ^= 0x01;
        let tamper_status = unsafe {
            (case.unwrap)(
                kek.as_ptr(),
                kek.len(),
                wrapped.as_ptr(),
                wrapped_len,
                unwrapped.as_mut_ptr(),
                unwrapped.len(),
                &mut unwrapped_len,
            )
        };
        assert_eq!(tamper_status, status::CRYPTO_AUTHENTICATION_FAILED);
    }
}

#[test]
fn c_abi_key_wrap_preserves_boundary_error_statuses() {
    let kek = bytes(aes_kw::AES256_KW_KEK_LEN, 0x41);
    let invalid_key_data = [0x22u8; aes_kw::AES_KW_BLOCK_LEN];
    let mut wrapped = [0u8; 24];
    let mut wrapped_len = 0usize;

    let invalid_plaintext_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_wrap_key(
            kek.as_ptr(),
            kek.len(),
            invalid_key_data.as_ptr(),
            invalid_key_data.len(),
            wrapped.as_mut_ptr(),
            wrapped.len(),
            &mut wrapped_len,
        )
    };
    assert_eq!(invalid_plaintext_status, status::CRYPTO_INVALID_ARGUMENT);

    let invalid_wrapped_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_unwrap_key(
            kek.as_ptr(),
            kek.len(),
            invalid_key_data.as_ptr(),
            invalid_key_data.len(),
            wrapped.as_mut_ptr(),
            wrapped.len(),
            &mut wrapped_len,
        )
    };
    assert_eq!(invalid_wrapped_status, status::CRYPTO_INVALID_CIPHERTEXT);
}

#[test]
fn c_abi_key_wrap_rejects_impossible_lengths_before_output_mutation() {
    let kek = bytes(aes_kw::AES256_KW_KEK_LEN, 0x51);
    let impossible_input = NonNull::<u8>::dangling().as_ptr();
    let mut output = [0xa5u8; 40];
    let mut written_len = 17usize;

    let wrap_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_wrap_key(
            kek.as_ptr(),
            kek.len(),
            impossible_input,
            usize::MAX,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        )
    };
    assert_eq!(wrap_status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(output, [0xa5u8; 40]);
    assert_eq!(written_len, 17);

    let unwrap_status = unsafe {
        aes_kw::rm_crypto_aes256_kw_unwrap_key(
            kek.as_ptr(),
            kek.len(),
            impossible_input,
            usize::MAX,
            output.as_mut_ptr(),
            output.len(),
            &mut written_len,
        )
    };
    assert_eq!(unwrap_status, status::CRYPTO_INVALID_ARGUMENT);
    assert_eq!(output, [0xa5u8; 40]);
    assert_eq!(written_len, 17);
}

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index).expect("test length fits in u8")))
        .collect()
}
