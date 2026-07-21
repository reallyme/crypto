// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_output_len_pair, write_fixed, write_len};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_core::KeyWrapAlgorithm;
use reallyme_crypto::aes_kw::{
    AesKwKeyData, AesKwWrappedKey, AES_128_KW_KEK_LENGTH, AES_192_KW_KEK_LENGTH,
    AES_256_KW_KEK_LENGTH, AES_KW_BLOCK_LENGTH, AES_KW_INTEGRITY_CHECK_LENGTH,
    AES_KW_MAX_KEY_DATA_LENGTH, AES_KW_MIN_KEY_DATA_LENGTH, AES_KW_MIN_WRAPPED_KEY_LENGTH,
};
use reallyme_crypto::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};

/// Length in bytes of an AES-128-KW key-encryption key.
pub const AES128_KW_KEK_LEN: usize = AES_128_KW_KEK_LENGTH;
/// Length in bytes of an AES-192-KW key-encryption key.
pub const AES192_KW_KEK_LEN: usize = AES_192_KW_KEK_LENGTH;
/// Length in bytes of an AES-256-KW key-encryption key.
pub const AES256_KW_KEK_LEN: usize = AES_256_KW_KEK_LENGTH;
/// RFC 3394 AES-KW block length in bytes.
pub const AES_KW_BLOCK_LEN: usize = AES_KW_BLOCK_LENGTH;
/// RFC 3394 AES-KW integrity-check length in bytes.
pub const AES_KW_INTEGRITY_LEN: usize = AES_KW_INTEGRITY_CHECK_LENGTH;
/// Minimum plaintext key-data length accepted by AES-KW.
pub const AES_KW_MIN_KEY_DATA_LEN: usize = AES_KW_MIN_KEY_DATA_LENGTH;
/// Minimum wrapped key-data length accepted by AES-KW.
pub const AES_KW_MIN_WRAPPED_KEY_LEN: usize = AES_KW_MIN_WRAPPED_KEY_LENGTH;
/// Maximum plaintext key-data length accepted by this ABI.
pub const AES_KW_MAX_KEY_DATA_LEN: usize = AES_KW_MAX_KEY_DATA_LENGTH;

fn map_wrap_error(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength | PrimitiveErrorReason::LengthOverflow,
        } => CRYPTO_INVALID_ARGUMENT,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        }
        | OperationError::Backend {
            reason: BackendErrorReason::Internal | BackendErrorReason::InvalidOutput,
        } => CRYPTO_INTERNAL_ERROR,
        _ => CRYPTO_INTERNAL_ERROR,
    }
}

fn map_unwrap_error(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => CRYPTO_AUTHENTICATION_FAILED,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        } => CRYPTO_INVALID_CIPHERTEXT,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        }
        | OperationError::Backend {
            reason: BackendErrorReason::Internal | BackendErrorReason::InvalidOutput,
        } => CRYPTO_INTERNAL_ERROR,
        _ => CRYPTO_INTERNAL_ERROR,
    }
}

type WrapOperation = fn(&[u8], &[u8]) -> Result<AesKwWrappedKey, OperationError>;
type UnwrapOperation = fn(&[u8], &[u8]) -> Result<AesKwKeyData, OperationError>;

struct AesKwRawBuffers {
    kek: *const u8,
    kek_len: usize,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len_out: *mut usize,
}

fn wrap_128(kek: &[u8], key_data: &[u8]) -> Result<AesKwWrappedKey, OperationError> {
    reallyme_crypto::operations::key_wrap::wrap_key(KeyWrapAlgorithm::Aes128Kw, kek, key_data)
}

fn wrap_192(kek: &[u8], key_data: &[u8]) -> Result<AesKwWrappedKey, OperationError> {
    reallyme_crypto::operations::key_wrap::wrap_key(KeyWrapAlgorithm::Aes192Kw, kek, key_data)
}

fn wrap_256(kek: &[u8], key_data: &[u8]) -> Result<AesKwWrappedKey, OperationError> {
    reallyme_crypto::operations::key_wrap::wrap_key(KeyWrapAlgorithm::Aes256Kw, kek, key_data)
}

fn unwrap_128(kek: &[u8], wrapped: &[u8]) -> Result<AesKwKeyData, OperationError> {
    reallyme_crypto::operations::key_wrap::unwrap_key(KeyWrapAlgorithm::Aes128Kw, kek, wrapped)
}

fn unwrap_192(kek: &[u8], wrapped: &[u8]) -> Result<AesKwKeyData, OperationError> {
    reallyme_crypto::operations::key_wrap::unwrap_key(KeyWrapAlgorithm::Aes192Kw, kek, wrapped)
}

fn unwrap_256(kek: &[u8], wrapped: &[u8]) -> Result<AesKwKeyData, OperationError> {
    reallyme_crypto::operations::key_wrap::unwrap_key(KeyWrapAlgorithm::Aes256Kw, kek, wrapped)
}

unsafe fn wrap_impl(
    buffers: AesKwRawBuffers,
    expected_kek_len: usize,
    operation: WrapOperation,
) -> CryptoStatus {
    let len_status =
        validate_output_len_pair(buffers.output, buffers.output_len, buffers.written_len_out);
    if len_status != CRYPTO_OK {
        return len_status;
    }
    // SAFETY: The exported boundary requires each input pointer to remain
    // valid and immutable for this call. `read_slice` also registers the
    // range so the later output write fails closed if the caller supplied
    // overlapping storage.
    let kek = match unsafe { read_slice(buffers.kek, buffers.kek_len) } {
        Ok(value) if value.len() == expected_kek_len => value,
        Ok(_) => return CRYPTO_INVALID_KEY,
        Err(status) => return status,
    };
    // SAFETY: The same boundary contract applies to the plaintext input;
    // the pointer helper validates the pair before constructing a slice.
    let key_data = match unsafe { read_slice(buffers.input, buffers.input_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    let expected_len = match key_data.len().checked_add(AES_KW_INTEGRITY_LEN) {
        Some(value) => value,
        None => return CRYPTO_INVALID_CIPHERTEXT,
    };
    if buffers.output_len < expected_len {
        return CRYPTO_BUFFER_TOO_SMALL;
    }
    let wrapped = match operation(kek, key_data) {
        Ok(value) => value,
        Err(error) => return map_wrap_error(error),
    };
    // SAFETY: `validate_output_len_pair` validated and registered the
    // caller-owned output capacity before any input references were made.
    // `write_fixed` rechecks capacity and rejects overlap with every
    // registered input before constructing the mutable slice.
    let write_status =
        unsafe { write_fixed(buffers.output, buffers.output_len, wrapped.as_bytes()) };
    if write_status != CRYPTO_OK {
        return write_status;
    }
    // SAFETY: The produced-length pointer was validated for alignment,
    // writability, and disjointness from the byte output above. The pointer
    // registry additionally rejects overlap with either caller input.
    unsafe { write_len(buffers.written_len_out, wrapped.len()) }
}

unsafe fn unwrap_impl(
    buffers: AesKwRawBuffers,
    expected_kek_len: usize,
    operation: UnwrapOperation,
) -> CryptoStatus {
    let len_status =
        validate_output_len_pair(buffers.output, buffers.output_len, buffers.written_len_out);
    if len_status != CRYPTO_OK {
        return len_status;
    }
    // SAFETY: The exported boundary requires each input pointer to remain
    // valid and immutable for this call. `read_slice` also registers the
    // range so the later plaintext write cannot alias the KEK.
    let kek = match unsafe { read_slice(buffers.kek, buffers.kek_len) } {
        Ok(value) if value.len() == expected_kek_len => value,
        Ok(_) => return CRYPTO_INVALID_KEY,
        Err(status) => return status,
    };
    // SAFETY: The same boundary contract applies to the wrapped input;
    // the pointer helper validates the pair before constructing a slice.
    let wrapped = match unsafe { read_slice(buffers.input, buffers.input_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    let expected_len = match wrapped.len().checked_sub(AES_KW_INTEGRITY_LEN) {
        Some(value) => value,
        None => return CRYPTO_INVALID_CIPHERTEXT,
    };
    if buffers.output_len < expected_len {
        return CRYPTO_BUFFER_TOO_SMALL;
    }
    let key_data = match operation(kek, wrapped) {
        Ok(value) => value,
        Err(error) => return map_unwrap_error(error),
    };
    // SAFETY: `validate_output_len_pair` validated and registered the
    // caller-owned output capacity before any input references were made.
    // `write_fixed` rechecks capacity and rejects overlap with every
    // registered input before constructing the mutable slice.
    let write_status =
        unsafe { write_fixed(buffers.output, buffers.output_len, key_data.as_bytes()) };
    if write_status != CRYPTO_OK {
        return write_status;
    }
    // SAFETY: The produced-length pointer was validated for alignment,
    // writability, and disjointness from the byte output above. The pointer
    // registry additionally rejects overlap with either caller input.
    unsafe { write_len(buffers.written_len_out, key_data.len()) }
}

macro_rules! export_aes_kw {
    ($wrap_name:ident, $unwrap_name:ident, $kek_len:expr, $wrap:expr, $unwrap:expr) => {
        #[doc = "Wraps plaintext key material with the selected RFC 3394 AES-KW suite."]
        ///
        /// # Safety
        ///
        /// Non-empty input pointers must reference initialized memory that
        /// remains valid and immutable for the duration of the call. The output
        /// pointer must reference `wrapped_out_len` writable bytes with
        /// exclusive ownership for the duration of the call.
        /// `wrapped_len_out` must be non-null, aligned, writable, and disjoint
        /// from every input and from `wrapped_out`. Input and output byte ranges
        /// must not overlap.
        #[no_mangle]
        pub unsafe extern "C" fn $wrap_name(
            kek: *const u8,
            kek_len: usize,
            key_data: *const u8,
            key_data_len: usize,
            wrapped_out: *mut u8,
            wrapped_out_len: usize,
            wrapped_len_out: *mut usize,
        ) -> CryptoStatus {
            ffi_guard(|| {
                // SAFETY: This boundary forwards the exact caller-supplied
                // pointer/length pairs under the contract documented above.
                // `wrap_impl` performs the runtime null, length, capacity,
                // alignment, and alias checks before constructing references.
                unsafe {
                    wrap_impl(
                        AesKwRawBuffers {
                            kek,
                            kek_len,
                            input: key_data,
                            input_len: key_data_len,
                            output: wrapped_out,
                            output_len: wrapped_out_len,
                            written_len_out: wrapped_len_out,
                        },
                        $kek_len,
                        $wrap,
                    )
                }
            })
        }

        #[doc = "Unwraps key material with the selected RFC 3394 AES-KW suite."]
        ///
        /// # Safety
        ///
        /// Non-empty input pointers must reference initialized memory that
        /// remains valid and immutable for the duration of the call. The output
        /// pointer must reference `key_data_out_len` writable bytes with
        /// exclusive ownership for the duration of the call.
        /// `key_data_len_out` must be non-null, aligned, writable, and disjoint
        /// from every input and from `key_data_out`. Input and output byte
        /// ranges must not overlap.
        #[no_mangle]
        pub unsafe extern "C" fn $unwrap_name(
            kek: *const u8,
            kek_len: usize,
            wrapped: *const u8,
            wrapped_len: usize,
            key_data_out: *mut u8,
            key_data_out_len: usize,
            key_data_len_out: *mut usize,
        ) -> CryptoStatus {
            ffi_guard(|| {
                // SAFETY: This boundary forwards the exact caller-supplied
                // pointer/length pairs under the contract documented above.
                // `unwrap_impl` performs the runtime null, length, capacity,
                // alignment, and alias checks before constructing references.
                unsafe {
                    unwrap_impl(
                        AesKwRawBuffers {
                            kek,
                            kek_len,
                            input: wrapped,
                            input_len: wrapped_len,
                            output: key_data_out,
                            output_len: key_data_out_len,
                            written_len_out: key_data_len_out,
                        },
                        $kek_len,
                        $unwrap,
                    )
                }
            })
        }
    };
}

export_aes_kw!(
    rm_crypto_aes128_kw_wrap_key,
    rm_crypto_aes128_kw_unwrap_key,
    AES128_KW_KEK_LEN,
    wrap_128,
    unwrap_128
);
export_aes_kw!(
    rm_crypto_aes192_kw_wrap_key,
    rm_crypto_aes192_kw_unwrap_key,
    AES192_KW_KEK_LEN,
    wrap_192,
    unwrap_192
);
export_aes_kw!(
    rm_crypto_aes256_kw_wrap_key,
    rm_crypto_aes256_kw_unwrap_key,
    AES256_KW_KEK_LEN,
    wrap_256,
    unwrap_256
);
