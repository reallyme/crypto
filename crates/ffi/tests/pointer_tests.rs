// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for C ABI pointer and length validation helpers.

#![allow(unsafe_code)]

use core::ptr::NonNull;
use crypto_ffi::guard::ffi_guard;
use crypto_ffi::pointer::{
    read_slice, validate_disjoint_input_len_pair, validate_disjoint_input_output_pair,
    validate_disjoint_len_outputs, validate_disjoint_output_pair, validate_len_output,
    validate_output_len_pair, write_fixed, write_i32, write_len, write_slice,
};
use crypto_ffi::sha2_256::{rm_crypto_sha2_256_digest, SHA2_256_DIGEST_LEN};
use crypto_ffi::status::{
    CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT, CRYPTO_OK,
};

#[test]
fn read_slice_accepts_null_only_for_empty_input() {
    let empty = unsafe { read_slice(core::ptr::null(), 0) };
    assert!(matches!(empty, Ok(value) if value.is_empty()));

    let status = unsafe { read_slice(core::ptr::null(), 1) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn read_slice_rejects_lengths_that_cannot_be_valid_rust_slices() {
    let ptr = NonNull::<u8>::dangling().as_ptr();
    let status = unsafe { read_slice(ptr, usize::MAX) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn write_slice_accepts_null_only_for_empty_output() {
    let empty = unsafe { write_slice(core::ptr::null_mut(), 0) };
    assert!(matches!(empty, Ok(value) if value.is_empty()));

    let status = unsafe { write_slice(core::ptr::null_mut(), 1) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn write_slice_rejects_lengths_that_cannot_be_valid_rust_slices() {
    let ptr = NonNull::<u8>::dangling().as_ptr();
    let status = unsafe { write_slice(ptr, usize::MAX) };
    assert_eq!(status, Err(CRYPTO_INVALID_ARGUMENT));
}

#[test]
fn write_fixed_rejects_small_buffers_without_mutating_them() {
    let mut output = [0xA5_u8; 2];
    let status = unsafe { write_fixed(output.as_mut_ptr(), output.len(), &[1, 2, 3]) };
    assert_eq!(status, CRYPTO_BUFFER_TOO_SMALL);
    assert_eq!(output, [0xA5, 0xA5]);
}

#[test]
fn write_fixed_rejects_overlapping_input_and_output_ranges() {
    let mut storage = [1_u8, 2, 3, 4, 0xA5, 0xA5, 0xA5, 0xA5];
    let input_ptr = storage.as_ptr();
    let output_ptr = unsafe { storage.as_mut_ptr().add(2) };
    let input = unsafe { core::slice::from_raw_parts(input_ptr, 4) };

    let status = unsafe { write_fixed(output_ptr, 4, input) };

    assert_eq!(status, CRYPTO_INVALID_ARGUMENT);
    assert_eq!(storage, [1, 2, 3, 4, 0xA5, 0xA5, 0xA5, 0xA5]);
}

#[test]
fn nested_ffi_guard_fails_without_clearing_outer_input_ranges() {
    let mut storage = [0xA5_u8; 64];
    let mut digest = [0_u8; SHA2_256_DIGEST_LEN];

    let status = ffi_guard(|| {
        let registered_len = match unsafe { read_slice(storage.as_ptr(), 32) } {
            Ok(value) => value.len(),
            Err(status) => return status,
        };
        if registered_len != 32 {
            return CRYPTO_INVALID_ARGUMENT;
        }

        let nested_status = unsafe {
            rm_crypto_sha2_256_digest(storage.as_ptr(), 32, digest.as_mut_ptr(), digest.len())
        };
        if nested_status != CRYPTO_INTERNAL_ERROR {
            return CRYPTO_INTERNAL_ERROR;
        }

        let overlap_status = unsafe { write_fixed(storage.as_mut_ptr(), storage.len(), &[1]) };
        if overlap_status != CRYPTO_INVALID_ARGUMENT {
            return CRYPTO_INTERNAL_ERROR;
        }
        CRYPTO_OK
    });

    assert_eq!(status, CRYPTO_OK);
}

#[test]
fn input_output_helpers_reject_partial_overlap() {
    let mut storage = [0_u8; 32];
    let input = storage.as_ptr();
    let output = unsafe { storage.as_mut_ptr().add(8) };

    assert_eq!(
        validate_disjoint_input_output_pair(input, 16, output, 16),
        CRYPTO_INVALID_ARGUMENT
    );

    let len_out = storage.as_mut_ptr().cast::<usize>();
    assert_eq!(
        validate_disjoint_input_len_pair(input, storage.len(), len_out),
        CRYPTO_INVALID_ARGUMENT
    );
}

#[test]
fn output_pair_helpers_reject_overlaps_without_writing() {
    let mut storage = [0_u8; 32];
    let first = storage.as_mut_ptr();
    let second = unsafe { storage.as_mut_ptr().add(8) };

    assert_eq!(
        validate_disjoint_output_pair(first, 16, second, 16),
        CRYPTO_INVALID_ARGUMENT
    );

    let len_out = unsafe { storage.as_mut_ptr().add(4).cast::<usize>() };
    assert_eq!(
        validate_output_len_pair(first, 16, len_out),
        CRYPTO_INVALID_ARGUMENT
    );

    let first_len = storage.as_mut_ptr().cast::<usize>();
    let second_len = unsafe { storage.as_mut_ptr().add(1).cast::<usize>() };
    assert_eq!(
        validate_disjoint_len_outputs(first_len, second_len),
        CRYPTO_INVALID_ARGUMENT
    );
}

#[test]
fn typed_output_writes_reject_null_and_misaligned_pointers() {
    assert_eq!(
        unsafe { write_len(core::ptr::null_mut(), 1) },
        CRYPTO_INVALID_ARGUMENT
    );
    assert_eq!(
        validate_len_output(core::ptr::null_mut()),
        CRYPTO_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe { write_i32(core::ptr::null_mut(), 1) },
        CRYPTO_INVALID_ARGUMENT
    );

    let mut usize_storage = [0_usize; 2];
    let misaligned_usize = usize_storage
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<usize>();
    assert_eq!(
        unsafe { write_len(misaligned_usize, 1) },
        CRYPTO_INVALID_ARGUMENT
    );

    let mut i32_storage = [0_i32; 2];
    let misaligned_i32 = i32_storage
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<i32>();
    assert_eq!(
        unsafe { write_i32(misaligned_i32, 1) },
        CRYPTO_INVALID_ARGUMENT
    );
}

#[test]
fn typed_output_writes_accept_aligned_pointers() {
    let mut len_out = 0_usize;
    let mut flag_out = 0_i32;

    assert_eq!(unsafe { write_len(&mut len_out, 7) }, CRYPTO_OK);
    assert_eq!(unsafe { write_i32(&mut flag_out, 1) }, CRYPTO_OK);
    assert_eq!(len_out, 7);
    assert_eq!(flag_out, 1);
}
