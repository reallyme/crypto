// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! C ABI wrapper for the Rust protobuf process lane.

use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_disjoint_input_len_pair, validate_disjoint_input_output_pair,
    validate_output_len_pair, write_fixed, write_len,
};
use crate::status::{
    CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_OK, CRYPTO_PROTO_ERROR,
};
use crypto_proto::wire::{CryptoProtoStatus, MAX_CRYPTO_PROTO_MESSAGE_BYTES};
use reallyme_crypto::proto_process::process_proto;

/// Run a protobuf-facing crypto operation through the shared Rust process lane.
///
/// The returned status is [`CRYPTO_OK`] when `output` contains successful
/// result protobuf bytes and [`CRYPTO_PROTO_ERROR`] when `output` contains
/// structured `CryptoError` protobuf bytes. Negative statuses describe ABI
/// failures such as invalid pointers or a too-small output buffer.
///
/// # Safety
///
/// Non-empty request and output ranges must point to initialized caller-owned
/// memory that remains valid for the duration of the call. `len_out` must point
/// to writable, aligned `usize` storage and must not overlap `output`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_process_proto(
    operation: u32,
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_len: usize,
    len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        if request_len > MAX_CRYPTO_PROTO_MESSAGE_BYTES {
            return CRYPTO_INVALID_ARGUMENT;
        }
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
        let mut result = process_proto(operation, request);
        let len_status = unsafe { write_len(len_out, result.len()) };
        if len_status != CRYPTO_OK {
            result.zeroize_bytes();
            return len_status;
        }
        if output_len < result.len() {
            result.zeroize_bytes();
            return CRYPTO_BUFFER_TOO_SMALL;
        }
        let write_status = unsafe { write_fixed(output_ptr, output_len, result.bytes()) };
        if write_status != CRYPTO_OK {
            result.zeroize_bytes();
            return write_status;
        }
        let status = match result.status {
            CryptoProtoStatus::Result => CRYPTO_OK,
            CryptoProtoStatus::CryptoError => CRYPTO_PROTO_ERROR,
            _ => CRYPTO_INTERNAL_ERROR,
        };
        result.zeroize_bytes();
        status
    })
}
