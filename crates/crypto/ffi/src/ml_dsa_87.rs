// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::status::{
    CryptoStatus, IntoKeypairResult, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK,
};

/// Length in bytes of an ML-DSA-87 public key (2592).
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
/// Length in bytes of an ML-DSA-87 secret-key seed (32).
pub const ML_DSA_87_SECRET_SEED_LEN: usize = 32;
/// Length in bytes of an ML-DSA-87 signature (4627).
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

/// Generates an ML-DSA-87 keypair, writing the 2592-byte public key to
/// `public_out` and the 32-byte secret seed to `secret_seed_out`.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes (at
/// least 2592) and `secret_seed_out` to at least `secret_seed_out_len`
/// writable bytes (at least 32); both must be non-null. Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success or a
/// negative error code. The caller owns the secret copy in `secret_seed_out`
/// and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_87_generate_keypair(
    public_out: *mut u8,
    public_out_len: usize,
    secret_seed_out: *mut u8,
    secret_seed_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status = validate_disjoint_output_pair(
            public_out,
            public_out_len,
            secret_seed_out,
            secret_seed_out_len,
        );
        if output_status != CRYPTO_OK {
            return output_status;
        }
        // `secret` is `Zeroizing<Vec<u8>>`: the Rust-side buffer is wiped when it
        // drops after being copied out. The caller owns the copy written to
        // `secret_seed_out` and is responsible for zeroizing it after use.
        let (public, secret) =
            match crypto_ml_dsa_87::generate_ml_dsa_87_keypair().into_keypair_result() {
                Ok(value) => value,
                Err(_) => return crate::status::CRYPTO_INTERNAL_ERROR,
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_seed_out, secret_seed_out_len, &secret) }
    })
}

/// Derives an ML-DSA-87 keypair from a caller-supplied 32-byte seed.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_87_generate_keypair_from_seed(
    secret_seed: *const u8,
    secret_seed_len: usize,
    public_out: *mut u8,
    public_out_len: usize,
    secret_seed_out: *mut u8,
    secret_seed_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status = validate_disjoint_output_pair(
            public_out,
            public_out_len,
            secret_seed_out,
            secret_seed_out_len,
        );
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let secret_seed = match unsafe { read_slice(secret_seed, secret_seed_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let secret_seed = match <&[u8; ML_DSA_87_SECRET_SEED_LEN]>::try_from(secret_seed) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let (public, secret) =
            match crypto_ml_dsa_87::generate_ml_dsa_87_keypair_from_seed(secret_seed) {
                Ok(value) => value,
                Err(_) => return CRYPTO_INVALID_KEY,
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_seed_out, secret_seed_out_len, &secret) }
    })
}

/// Signs `message` with the ML-DSA-87 `secret_seed`, writing the 4627-byte
/// signature to `signature_out`.
///
/// # Safety
///
/// `secret_seed` must be valid for `secret_seed_len` bytes (must be 32) and
/// `message` for `message_len` bytes; a pointer may be null only when its
/// length is `0`. `signature_out` must be non-null and point to at least
/// `signature_out_len` writable bytes (at least [`ML_DSA_87_SIGNATURE_LEN`],
/// 4627). Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on
/// success, or [`CRYPTO_INVALID_KEY`] for a bad seed length or key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_87_sign(
    secret_seed: *const u8,
    secret_seed_len: usize,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
    signature_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let secret_seed = match unsafe { read_slice(secret_seed, secret_seed_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if secret_seed.len() != ML_DSA_87_SECRET_SEED_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match crypto_ml_dsa_87::sign_ml_dsa_87(secret_seed, message) {
            Ok(value) => unsafe { write_fixed(signature_out, signature_out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Verifies an ML-DSA-87 `signature` over `message` against `public_key`,
/// writing `1` (valid) or `0` (invalid) to `valid_out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 2592),
/// `message` for `message_len` bytes, and `signature` for `signature_len`
/// bytes (must be 4627); a pointer may be null only when its length is `0`.
/// `valid_out` must be non-null and point to a writable `i32`. Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] when the check ran
/// (result in `valid_out`), [`CRYPTO_INVALID_KEY`] for a bad public-key
/// length, or [`CRYPTO_INVALID_SIGNATURE`] for a bad signature length or
/// verification error.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_87_verify(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let signature = match unsafe { read_slice(signature, signature_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if signature.len() != ML_DSA_87_SIGNATURE_LEN {
            return CRYPTO_INVALID_SIGNATURE;
        }
        match crypto_ml_dsa_87::verify_ml_dsa_87(public_key, message, signature) {
            Ok(()) => CRYPTO_OK,
            Err(_) => CRYPTO_INVALID_SIGNATURE,
        }
    })
}

/// Validates a 2592-byte ML-DSA-87 `public_key` and copies its canonical
/// encoding to `out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 2592; may be
/// null only when the length is `0`). `out` must be non-null and point to at
/// least `out_len` writable bytes (at least 2592). Returns [`CryptoStatus`]
/// via the return value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`]
/// for a bad key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_87_encode_public_key(
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
        if public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        unsafe { write_fixed(out, out_len, public_key) }
    })
}

/// Validates a 2592-byte encoded ML-DSA-87 `public_key` and copies the decoded
/// raw public key to `out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 2592; may be
/// null only when the length is `0`). `out` must be non-null and point to at
/// least `out_len` writable bytes (at least 2592). Returns [`CryptoStatus`]
/// via the return value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`]
/// for a bad key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_87_decode_public_key(
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
        if public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        unsafe { write_fixed(out, out_len, public_key) }
    })
}
