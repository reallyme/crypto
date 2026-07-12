// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_disjoint_output_pair, validate_output_len_pair, write_fixed, write_len,
};
use crate::status::{
    CryptoStatus, IntoKeypairResult, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK,
};

/// Length in bytes of a P-384 secret key.
pub const P384_SECRET_KEY_LEN: usize = crypto_p384::P384_SECRET_KEY_LEN;
/// Length in bytes of a SEC1 compressed P-384 public key.
pub const P384_PUBLIC_KEY_COMPRESSED_LEN: usize = crypto_p384::P384_PUBLIC_KEY_COMPRESSED_LEN;
/// Length in bytes of a SEC1 uncompressed P-384 public key.
pub const P384_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = crypto_p384::P384_PUBLIC_KEY_UNCOMPRESSED_LEN;
/// Length in bytes of a raw P-384 ECDH shared secret.
pub const P384_SHARED_SECRET_LEN: usize = crypto_p384::P384_SHARED_SECRET_LEN;
/// Maximum length in bytes of a DER-encoded P-384 ECDSA signature.
pub const P384_SIGNATURE_DER_MAX_LEN: usize = crypto_p384::P384_SIGNATURE_DER_MAX_LEN;

/// Generates a P-384 keypair.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p384_generate_keypair(
    public_out: *mut u8,
    public_out_len: usize,
    secret_out: *mut u8,
    secret_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status =
            validate_disjoint_output_pair(public_out, public_out_len, secret_out, secret_out_len);
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let (public, secret) = match crypto_p384::generate_p384_keypair().into_keypair_result() {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &secret) }
    })
}

/// Derives a P-384 keypair from a caller-supplied 48-byte secret scalar.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p384_generate_keypair_from_secret_key(
    secret_key: *const u8,
    secret_key_len: usize,
    public_out: *mut u8,
    public_out_len: usize,
    secret_out: *mut u8,
    secret_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status =
            validate_disjoint_output_pair(public_out, public_out_len, secret_out, secret_out_len);
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let secret_key = match <&[u8; P384_SECRET_KEY_LEN]>::try_from(secret_key) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let (public, secret) = match crypto_p384::generate_p384_keypair_from_secret_key(secret_key)
        {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &secret) }
    })
}

/// Signs a message with P-384 ECDSA/SHA-384 and writes a DER signature.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p384_sign_der_prehash(
    secret_key: *const u8,
    secret_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
    signature_out_len: usize,
    signature_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let len_status =
            validate_output_len_pair(signature_out, signature_out_len, signature_len_out);
        if len_status != CRYPTO_OK {
            return len_status;
        }
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if secret_key.len() != P384_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let signature = match crypto_p384::sign_p384_der_prehash(secret_key, message) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        if signature_out_len < signature.len() {
            return CRYPTO_BUFFER_TOO_SMALL;
        }
        let status = unsafe { write_fixed(signature_out, signature_out_len, &signature) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(signature_len_out, signature.len()) }
    })
}

/// Verifies a DER-encoded P-384 ECDSA/SHA-384 signature.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p384_verify_der_prehash(
    signature: *const u8,
    signature_len: usize,
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let signature = match unsafe { read_slice(signature, signature_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if public_key.len() != P384_PUBLIC_KEY_COMPRESSED_LEN
            && public_key.len() != P384_PUBLIC_KEY_UNCOMPRESSED_LEN
        {
            return CRYPTO_INVALID_KEY;
        }
        match crypto_p384::verify_p384_der_prehash(signature, message, public_key) {
            Ok(()) => CRYPTO_OK,
            Err(_) => CRYPTO_INVALID_SIGNATURE,
        }
    })
}

/// Performs P-384 ECDH between `secret_key` and `public_key`, writing the raw
/// 48-byte shared-secret x-coordinate to `shared_secret_out`.
///
/// # Safety
///
/// `secret_key` must be valid for `secret_key_len` bytes (must be 48) and
/// `public_key` for `public_key_len` bytes (49 compressed or 97
/// uncompressed); either pointer may be null only when its length is `0`.
/// `shared_secret_out` must be non-null and point to at least
/// `shared_secret_out_len` writable bytes (at least 48). The caller owns the
/// secret copy in `shared_secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p384_derive_shared_secret(
    secret_key: *const u8,
    secret_key_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    shared_secret_out: *mut u8,
    shared_secret_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match crypto_p384::derive_p384_shared_secret(secret_key, public_key) {
            Ok(value) => unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Converts a P-384 public key to compressed SEC1 form.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p384_compress_public_key(
    public_key_uncompressed: *const u8,
    public_key_uncompressed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key =
            match unsafe { read_slice(public_key_uncompressed, public_key_uncompressed_len) } {
                Ok(value) => value,
                Err(status) => return status,
            };
        match crypto_p384::compress_p384(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Converts a P-384 public key to uncompressed SEC1 form.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p384_decompress_public_key(
    public_key_compressed: *const u8,
    public_key_compressed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key =
            match unsafe { read_slice(public_key_compressed, public_key_compressed_len) } {
                Ok(value) => value,
                Err(status) => return status,
            };
        match crypto_p384::decompress_p384(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}
