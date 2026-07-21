// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{
    CryptoStatus, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_core::{CryptoError, KdfFailureKind};
use reallyme_crypto::kmac::{
    Kmac256Key, KMAC256_MAX_CONTEXT_LENGTH, KMAC256_MAX_CUSTOMIZATION_LENGTH,
    KMAC256_MAX_KEY_LENGTH, KMAC256_MAX_OUTPUT_LENGTH, KMAC256_MIN_KEY_LENGTH,
};

/// Minimum KMAC256 key length in bytes.
pub const KMAC256_MIN_KEY_LEN: usize = KMAC256_MIN_KEY_LENGTH;
/// Maximum KMAC256 key length accepted by this ABI.
pub const KMAC256_MAX_KEY_LEN: usize = KMAC256_MAX_KEY_LENGTH;
/// Maximum KMAC256 context length accepted by this ABI.
pub const KMAC256_MAX_CONTEXT_LEN: usize = KMAC256_MAX_CONTEXT_LENGTH;
/// Maximum KMAC256 customization length accepted by this ABI.
pub const KMAC256_MAX_CUSTOMIZATION_LEN: usize = KMAC256_MAX_CUSTOMIZATION_LENGTH;
/// Maximum KMAC256 output length accepted by this ABI.
pub const KMAC256_MAX_OUTPUT_LEN: usize = KMAC256_MAX_OUTPUT_LENGTH;

fn map_error(error: CryptoError) -> CryptoStatus {
    match error {
        CryptoError::Kdf {
            kind: KdfFailureKind::InvalidSecretLength,
            ..
        } => CRYPTO_INVALID_KEY,
        CryptoError::Kdf {
            kind: KdfFailureKind::InvalidOutputLength | KdfFailureKind::InvalidParams,
            ..
        } => CRYPTO_INVALID_ARGUMENT,
        _ => CRYPTO_INTERNAL_ERROR,
    }
}

/// Derives key material with KMAC256.
///
/// # Safety
///
/// Each input pointer must be valid for its matching length. `output` must be
/// valid for `output_len` writable bytes. Input and output regions must not
/// overlap.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_kmac256_derive(
    key: *const u8,
    key_len: usize,
    context: *const u8,
    context_len: usize,
    customization: *const u8,
    customization_len: usize,
    output: *mut u8,
    output_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        if key_len > KMAC256_MAX_KEY_LENGTH {
            return CRYPTO_INVALID_KEY;
        }
        if output_len == 0
            || output_len > KMAC256_MAX_OUTPUT_LENGTH
            || context_len > KMAC256_MAX_CONTEXT_LENGTH
            || customization_len > KMAC256_MAX_CUSTOMIZATION_LENGTH
        {
            return CRYPTO_INVALID_ARGUMENT;
        }
        // SAFETY: This zero-length copy validates the caller's output
        // pointer/capacity pair without reading or modifying its contents.
        // The final write rechecks the pair after all inputs are registered.
        let output_status = unsafe { write_fixed(output, output_len, &[]) };
        if output_status != CRYPTO_OK {
            return output_status;
        }
        // SAFETY: The exported contract requires the key pointer to remain
        // valid and immutable for the duration of this call. The pointer helper
        // validates the pair and registers it for the final alias check.
        let key = match unsafe { read_slice(key, key_len) } {
            Ok(value) => match Kmac256Key::from_slice(value) {
                Ok(key) => key,
                Err(error) => return map_error(error),
            },
            Err(status) => return status,
        };
        // SAFETY: The exported contract covers the context pointer, and the
        // helper rejects invalid pairs before constructing a shared slice.
        let context = match unsafe { read_slice(context, context_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        // SAFETY: The exported contract covers the customization pointer, and
        // the helper rejects invalid pairs before constructing a shared slice.
        let customization = match unsafe { read_slice(customization, customization_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let derived = match reallyme_crypto::operations::kdf::derive_kmac256(
            &key,
            context,
            customization,
            output_len,
        ) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_ARGUMENT,
        };
        if derived.len() != output_len {
            return CRYPTO_INTERNAL_ERROR;
        }
        // SAFETY: The output pair was validated above. `write_fixed` rechecks
        // capacity and rejects overlap with the registered key, context, and
        // customization inputs before constructing the mutable output slice.
        unsafe { write_fixed(output, output_len, derived.as_bytes()) }
    })
}
