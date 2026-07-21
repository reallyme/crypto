// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_disjoint_output_pair, validate_output_len_pair, write_fixed, write_len,
};
use crate::signature_status::{key_management_status, sign_status, verify_status};
use crate::status::{CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INVALID_KEY, CRYPTO_OK};
use crypto_core::Algorithm;
use reallyme_crypto::operations::key_encoding;
use reallyme_crypto::p256 as crypto_p256;

/// Length in bytes of a P-256 secret key (32).
pub const P256_SECRET_KEY_LEN: usize = 32;
/// Length in bytes of a SEC1 compressed P-256 public key (33).
pub const P256_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
/// Length in bytes of a SEC1 uncompressed P-256 public key (65).
pub const P256_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
/// Length in bytes of a raw P-256 ECDH shared secret (32).
pub const P256_SHARED_SECRET_LEN: usize = 32;
/// Maximum length in bytes of a DER-encoded P-256 ECDSA signature.
pub const P256_SIGNATURE_DER_MAX_LEN: usize = crypto_p256::P256_SIGNATURE_DER_MAX_LEN;

/// Generates a P-256 keypair, writing the SEC1 public key to `public_out` and
/// the 32-byte secret key to `secret_out`.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes and
/// `secret_out` to at least `secret_out_len` writable bytes (at least 32);
/// both must be non-null. Returns [`CryptoStatus`] via the return value:
/// [`CRYPTO_OK`] on success or a negative error code. The caller owns the
/// secret copy in `secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p256_generate_keypair(
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
        // `secret` is `Zeroizing<Vec<u8>>`: the Rust-side buffer is wiped when it
        // drops after being copied out. The caller owns the copy written to
        // `secret_out` and is responsible for zeroizing it after use.
        let key_pair =
            match reallyme_crypto::operations::signature::generate_key_pair(Algorithm::P256) {
                Ok(value) => value,
                Err(error) => return key_management_status(error),
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &key_pair.secret_key) }
    })
}

/// Derives a P-256 keypair from a caller-supplied 32-byte secret scalar.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p256_generate_keypair_from_secret_key(
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
        let secret_key = match <&[u8; P256_SECRET_KEY_LEN]>::try_from(secret_key) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let key_pair = match reallyme_crypto::operations::signature::derive_key_pair(
            Algorithm::P256,
            secret_key,
        ) {
            Ok(value) => value,
            Err(error) => return key_management_status(error),
        };
        let status = unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &key_pair.secret_key) }
    })
}

/// Hashes `message` exactly once with SHA-256, signs it with the P-256
/// `secret_key`, and writes the DER-encoded ECDSA signature to
/// `signature_out` and its actual length to `signature_len_out`.
///
/// # Safety
///
/// `secret_key` must be valid for `secret_key_len` bytes (must be 32) and
/// `message` for `message_len` bytes; a pointer may be null only when its
/// length is `0`. `signature_out` must be non-null and point to at least
/// `signature_out_len` writable bytes (up to [`P256_SIGNATURE_DER_MAX_LEN`]).
/// `signature_len_out` must be a non-null writable `usize`. Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success,
/// [`CRYPTO_INVALID_KEY`] for a bad key, or [`CRYPTO_BUFFER_TOO_SMALL`].
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p256_sign_der_prehash(
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
        if secret_key.len() != P256_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let signature = match reallyme_crypto::operations::signature::sign(
            Algorithm::P256,
            secret_key,
            message,
        ) {
            Ok(value) => value,
            Err(error) => return sign_status(error),
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

/// Verifies a DER-encoded P-256 ECDSA/SHA-256 `signature` over `message`
/// against `public_key`.
///
/// # Safety
///
/// `signature` must be valid for `signature_len` bytes, `message` for
/// `message_len` bytes, and `public_key` for `public_key_len` bytes (33
/// compressed or 65 uncompressed); a pointer may be null only when its length
/// is `0`. Returns [`CRYPTO_OK`] only when the signature is valid.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p256_verify_der_prehash(
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
        if public_key.len() != P256_PUBLIC_KEY_COMPRESSED_LEN
            && public_key.len() != P256_PUBLIC_KEY_UNCOMPRESSED_LEN
        {
            return CRYPTO_INVALID_KEY;
        }
        match reallyme_crypto::operations::signature::verify(
            Algorithm::P256,
            public_key,
            message,
            signature,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
        }
    })
}

/// Performs P-256 ECDH between `secret_key` and `public_key`, writing the raw
/// 32-byte shared-secret x-coordinate to `shared_secret_out`.
///
/// # Safety
///
/// `secret_key` must be valid for `secret_key_len` bytes (must be 32) and
/// `public_key` for `public_key_len` bytes (33 compressed or 65
/// uncompressed); either pointer may be null only when its length is `0`.
/// `shared_secret_out` must be non-null and point to at least
/// `shared_secret_out_len` writable bytes (at least 32). Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success, or
/// [`CRYPTO_INVALID_KEY`] for an invalid key. The caller owns the secret copy
/// in `shared_secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p256_derive_shared_secret(
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
        // The derived secret is `Zeroizing<Vec<u8>>`: the Rust-side buffer is
        // wiped on drop after the copy out. The caller owns the copy written to
        // `shared_secret_out` and is responsible for zeroizing it after use.
        match reallyme_crypto::operations::key_agreement::derive_shared_secret(
            Algorithm::P256,
            secret_key,
            public_key,
        ) {
            Ok(value) => unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &value) },
            Err(error) => crate::key_agreement_status::key_agreement_status(error),
        }
    })
}

/// Converts an uncompressed (65-byte) P-256 public key to its 33-byte
/// SEC1 compressed form, writing the result to `out`.
///
/// # Safety
///
/// `public_key_uncompressed` must be valid for `public_key_uncompressed_len`
/// bytes (may be null only when that length is `0`). `out` must be non-null
/// and point to at least `out_len` writable bytes (at least 33). Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success, or
/// [`CRYPTO_INVALID_KEY`] for an invalid key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p256_compress_public_key(
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
        match key_encoding::compress_p256_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Converts a compressed (33-byte) P-256 public key to its 65-byte
/// SEC1 uncompressed form, writing the result to `out`.
///
/// # Safety
///
/// `public_key_compressed` must be valid for `public_key_compressed_len` bytes
/// (may be null only when that length is `0`). `out` must be non-null and
/// point to at least `out_len` writable bytes (at least 65). Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success, or
/// [`CRYPTO_INVALID_KEY`] for an invalid key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_p256_decompress_public_key(
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
        match key_encoding::decompress_p256_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}
