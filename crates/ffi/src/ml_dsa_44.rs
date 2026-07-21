// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::signature_status::{key_management_status, sign_status, verify_status};
use crate::status::{CryptoStatus, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK};
use crypto_core::Algorithm;
use reallyme_crypto::operations::key_encoding;

/// Length in bytes of an ML-DSA-44 public key (1312).
pub const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
/// Length in bytes of an ML-DSA-44 secret-key seed (32).
pub const ML_DSA_44_SECRET_SEED_LEN: usize = 32;
/// Length in bytes of an ML-DSA-44 signature (2420).
pub const ML_DSA_44_SIGNATURE_LEN: usize = 2420;

/// Generates an ML-DSA-44 keypair, writing the 1312-byte public key to
/// `public_out` and the 32-byte secret seed to `secret_seed_out`.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes (at
/// least 1312) and `secret_seed_out` to at least `secret_seed_out_len`
/// writable bytes (at least 32); both must be non-null. Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success or a
/// negative error code. The caller owns the secret copy in `secret_seed_out`
/// and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_44_generate_keypair(
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
        let key_pair =
            match reallyme_crypto::operations::signature::generate_key_pair(Algorithm::MlDsa44) {
                Ok(value) => value,
                Err(error) => return key_management_status(error),
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_seed_out, secret_seed_out_len, &key_pair.secret_key) }
    })
}

/// Derives an ML-DSA-44 keypair from a caller-supplied 32-byte seed.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_44_generate_keypair_from_seed(
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
        let secret_seed = match <&[u8; ML_DSA_44_SECRET_SEED_LEN]>::try_from(secret_seed) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let key_pair = match reallyme_crypto::operations::signature::derive_key_pair(
            Algorithm::MlDsa44,
            secret_seed,
        ) {
            Ok(value) => value,
            Err(error) => return key_management_status(error),
        };
        let status = unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_seed_out, secret_seed_out_len, &key_pair.secret_key) }
    })
}

/// Signs `message` with the ML-DSA-44 `secret_seed`, writing the 2420-byte
/// signature to `signature_out`.
///
/// # Safety
///
/// `secret_seed` must be valid for `secret_seed_len` bytes (must be 32) and
/// `message` for `message_len` bytes; a pointer may be null only when its
/// length is `0`. `signature_out` must be non-null and point to at least
/// `signature_out_len` writable bytes (at least [`ML_DSA_44_SIGNATURE_LEN`],
/// 2420). Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on
/// success, or [`CRYPTO_INVALID_KEY`] for a bad seed length or key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_44_sign(
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
        if secret_seed.len() != ML_DSA_44_SECRET_SEED_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match reallyme_crypto::operations::signature::sign(Algorithm::MlDsa44, secret_seed, message)
        {
            Ok(value) => unsafe { write_fixed(signature_out, signature_out_len, &value) },
            Err(error) => sign_status(error),
        }
    })
}

/// Verifies an ML-DSA-44 `signature` over `message` against `public_key`,
/// writing `1` (valid) or `0` (invalid) to `valid_out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 1312),
/// `message` for `message_len` bytes, and `signature` for `signature_len`
/// bytes (must be 2420); a pointer may be null only when its length is `0`.
/// `valid_out` must be non-null and point to a writable `i32`. Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] when the check ran
/// (result in `valid_out`), [`CRYPTO_INVALID_KEY`] for a bad public-key
/// length, or [`CRYPTO_INVALID_SIGNATURE`] for a bad signature length or
/// verification error.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_44_verify(
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
        if public_key.len() != ML_DSA_44_PUBLIC_KEY_LEN {
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
        if signature.len() != ML_DSA_44_SIGNATURE_LEN {
            return CRYPTO_INVALID_SIGNATURE;
        }
        match reallyme_crypto::operations::signature::verify(
            Algorithm::MlDsa44,
            public_key,
            message,
            signature,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
        }
    })
}

/// Validates a 1312-byte ML-DSA-44 `public_key` and copies its canonical
/// encoding to `out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 1312; may be
/// null only when the length is `0`). `out` must be non-null and point to at
/// least `out_len` writable bytes (at least 1312). Returns [`CryptoStatus`]
/// via the return value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`]
/// for a bad key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_44_encode_public_key(
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
        match key_encoding::copy_fixed_public_key(public_key, ML_DSA_44_PUBLIC_KEY_LEN) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Validates a 1312-byte encoded ML-DSA-44 `public_key` and copies the decoded
/// raw public key to `out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 1312; may be
/// null only when the length is `0`). `out` must be non-null and point to at
/// least `out_len` writable bytes (at least 1312). Returns [`CryptoStatus`]
/// via the return value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`]
/// for a bad key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_dsa_44_decode_public_key(
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
        match key_encoding::copy_fixed_public_key(public_key, ML_DSA_44_PUBLIC_KEY_LEN) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}
