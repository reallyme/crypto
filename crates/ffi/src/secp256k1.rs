// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::signature_status::{key_management_status, sign_status, verify_status};
use crate::status::{CryptoStatus, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK};
use crypto_core::Algorithm;
use reallyme_crypto::operations::key_encoding;

/// Length in bytes of a secp256k1 secret key (32).
pub const SECP256K1_SECRET_KEY_LEN: usize = 32;
/// Length in bytes of a SEC1 compressed secp256k1 public key (33).
pub const SECP256K1_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
/// Length in bytes of a SEC1 uncompressed secp256k1 public key (65).
pub const SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
/// Length in bytes of a secp256k1 compact (r‖s) ECDSA signature (64).
pub const SECP256K1_SIGNATURE_LEN: usize = 64;

/// Generates a secp256k1 keypair, writing the SEC1 public key to `public_out`
/// and the 32-byte secret key to `secret_out`.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes and
/// `secret_out` to at least `secret_out_len` writable bytes (at least 32);
/// both must be non-null. Returns [`CryptoStatus`] via the return value:
/// [`CRYPTO_OK`] on success or a negative error code. The caller owns the
/// secret copy in `secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_secp256k1_generate_keypair(
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
            match reallyme_crypto::operations::signature::generate_key_pair(Algorithm::Secp256k1) {
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

/// Derives a secp256k1 keypair from a caller-supplied 32-byte secret scalar.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_secp256k1_generate_keypair_from_secret_key(
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
        let secret_key = match <&[u8; SECP256K1_SECRET_KEY_LEN]>::try_from(secret_key) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let key_pair = match reallyme_crypto::operations::signature::derive_key_pair(
            Algorithm::Secp256k1,
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

/// Signs `message` with the secp256k1 `secret_key`, writing the 64-byte
/// compact ECDSA signature to `signature_out`.
///
/// The function hashes `message` internally exactly once with SHA-256
/// (callers pass the full message, not a pre-computed digest) and produces a
/// deterministic (RFC 6979) ECDSA signature normalized to low-S (BIP 0062),
/// encoded as the 64-byte compact `r ‖ s` form.
///
/// # Safety
///
/// `secret_key` must be valid for `secret_key_len` bytes (must be 32) and
/// `message` for `message_len` bytes; a pointer may be null only when its
/// length is `0`. `signature_out` must be non-null and point to at least
/// `signature_out_len` writable bytes (at least [`SECP256K1_SIGNATURE_LEN`],
/// 64). Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on
/// success, or [`CRYPTO_INVALID_KEY`] for a bad key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_secp256k1_sign(
    secret_key: *const u8,
    secret_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
    signature_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if secret_key.len() != SECP256K1_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match reallyme_crypto::operations::signature::sign(
            Algorithm::Secp256k1,
            secret_key,
            message,
        ) {
            Ok(value) => unsafe { write_fixed(signature_out, signature_out_len, &value) },
            Err(error) => sign_status(error),
        }
    })
}

/// Verifies a 64-byte compact secp256k1 ECDSA `signature` over `message`
/// against `public_key`.
///
/// # Safety
///
/// `signature` must be valid for `signature_len` bytes (must be 64), `message`
/// for `message_len` bytes, and `public_key` for `public_key_len` bytes (33
/// compressed or 65 uncompressed); a pointer may be null only when its length
/// is `0`. Returns [`CRYPTO_OK`] only when the signature is valid.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_secp256k1_verify(
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
        if signature.len() != SECP256K1_SIGNATURE_LEN {
            return CRYPTO_INVALID_SIGNATURE;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if public_key.len() != SECP256K1_PUBLIC_KEY_COMPRESSED_LEN
            && public_key.len() != SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN
        {
            return CRYPTO_INVALID_KEY;
        }
        match reallyme_crypto::operations::signature::verify(
            Algorithm::Secp256k1,
            public_key,
            message,
            signature,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
        }
    })
}

/// Validates a compressed secp256k1 `public_key` and writes it to `out`
/// unchanged.
///
/// This crate's canonical secp256k1 public-key form is the 33-byte
/// compressed SEC1 encoding (`0x02`/`0x03` prefix). This checks that shape
/// (length and prefix) and copies the key byte-for-byte; it does not
/// re-serialize, and it does not verify the point lies on the curve — use
/// [`rm_crypto_secp256k1_decompress_public_key`] when full point validation
/// or the uncompressed form is required.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `out` must be non-null and point to at least
/// `out_len` writable bytes (33). Returns [`CryptoStatus`] via the return
/// value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`] for input that
/// is not a 33-byte `0x02`/`0x03`-prefixed key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_secp256k1_encode_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match key_encoding::encode_secp256k1_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Decodes a secp256k1 `public_key` and writes the canonical key bytes to
/// `out`.
///
/// This is the inverse of [`rm_crypto_secp256k1_encode_public_key`], and it has
/// the same representation on both sides: 33-byte compressed SEC1. It validates
/// length and prefix, then copies the key byte-for-byte; use
/// [`rm_crypto_secp256k1_decompress_public_key`] when full point validation is
/// required.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `out` must be non-null and point to at least
/// `out_len` writable bytes (33). Returns [`CryptoStatus`] via the return
/// value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`] for an invalid
/// encoding.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_secp256k1_decode_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match key_encoding::decode_secp256k1_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Decompresses a secp256k1 `public_key` into its affine coordinates, writing
/// the 32-byte x-coordinate to `x_out` and the 32-byte y-coordinate to `y_out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `x_out` and `y_out` must each be non-null and
/// point to at least `x_out_len` / `y_out_len` writable bytes (at least 32
/// each). Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on
/// success, or [`CRYPTO_INVALID_KEY`] for an invalid key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_secp256k1_decompress_public_key(
    public_key: *const u8,
    public_key_len: usize,
    x_out: *mut u8,
    x_out_len: usize,
    y_out: *mut u8,
    y_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status = validate_disjoint_output_pair(x_out, x_out_len, y_out, y_out_len);
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let (x, y) = match key_encoding::decompress_secp256k1_public_key(public_key) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let status = unsafe { write_fixed(x_out, x_out_len, &x) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(y_out, y_out_len, &y) }
    })
}
