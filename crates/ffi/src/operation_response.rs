// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! C ABI wrapper for the generated operation-response lane.

use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_disjoint_input_len_pair, validate_disjoint_input_output_pair,
    validate_output_len_pair, write_fixed, write_len,
};
use crate::status::{CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INVALID_ARGUMENT, CRYPTO_OK};
use reallyme_crypto::operation_contract::{
    process_operation_response, process_operation_response_json,
};
use zeroize::{Zeroize, Zeroizing};

type OperationResponseFunction = fn(&[u8]) -> Zeroizing<Vec<u8>>;

/// Run a protobuf-facing crypto operation and return `CryptoOperationResponse`.
///
/// The C return status reports only ABI success or failure. Operation success
/// and failure are represented by the generated response oneof.
///
/// # Safety
///
/// Non-empty request and output ranges must point to initialized caller-owned
/// memory that remains valid for the duration of the call. `len_out` must point
/// to writable, aligned `usize` storage and must not overlap `output`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_process_operation_response(
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_len: usize,
    len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        process_request(
            request_ptr,
            request_len,
            output_ptr,
            output_len,
            len_out,
            process_operation_response,
        )
    })
}

/// Run a generated ProtoJSON crypto request and return `CryptoOperationResponse`.
///
/// JSON is request-only. The output is the same binary generated response
/// returned by [`rm_crypto_process_operation_response`].
///
/// # Safety
///
/// The pointer, length, output, aliasing, and ownership requirements are
/// identical to [`rm_crypto_process_operation_response`].
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_process_operation_response_json(
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_len: usize,
    len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        process_request(
            request_ptr,
            request_len,
            output_ptr,
            output_len,
            len_out,
            process_operation_response_json,
        )
    })
}

fn process_request(
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_len: usize,
    len_out: *mut usize,
    process: OperationResponseFunction,
) -> CryptoStatus {
    if validate_output_len_pair(output_ptr, output_len, len_out) != CRYPTO_OK {
        return CRYPTO_INVALID_ARGUMENT;
    }
    if validate_disjoint_input_output_pair(request_ptr, request_len, output_ptr, output_len)
        != CRYPTO_OK
        || validate_disjoint_input_len_pair(request_ptr, request_len, len_out) != CRYPTO_OK
    {
        return CRYPTO_INVALID_ARGUMENT;
    }
    let request = match unsafe { read_slice(request_ptr, request_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut result = process(request);
    let len_status = unsafe { write_len(len_out, result.len()) };
    if len_status != CRYPTO_OK {
        result.zeroize();
        return len_status;
    }
    if output_len < result.len() {
        result.zeroize();
        return CRYPTO_BUFFER_TOO_SMALL;
    }
    let write_status = unsafe { write_fixed(output_ptr, output_len, result.as_slice()) };
    if write_status != CRYPTO_OK {
        result.zeroize();
        return write_status;
    }
    result.zeroize();
    CRYPTO_OK
}
