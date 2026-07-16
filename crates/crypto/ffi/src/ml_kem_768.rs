// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::status::{
    CryptoStatus, IntoKeypairResult, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};

/// Length in bytes of an ML-KEM-768 public key (1184).
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
/// Length in bytes of an ML-KEM-768 secret key as handled here (64).
pub const ML_KEM_768_SECRET_KEY_LEN: usize = 64;
/// Length in bytes of an ML-KEM-768 ciphertext (1088).
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// Length in bytes of an ML-KEM-768 shared secret (32).
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;
/// Length in bytes of ML-KEM deterministic encapsulation randomness.
pub const ML_KEM_768_ENCAPS_RANDOMNESS_LEN: usize = 32;

/// Generates an ML-KEM-768 keypair, writing the 1184-byte public key to
/// `public_out` and the 64-byte secret key to `secret_out`.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes (at
/// least 1184) and `secret_out` to at least `secret_out_len` writable bytes
/// (at least 64); both must be non-null. Returns [`CryptoStatus`] via the
/// return value: [`CRYPTO_OK`] on success or a negative error code. The caller
/// owns the secret copy in `secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_kem_768_generate_keypair(
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
        let (public, secret) =
            match crypto_ml_kem_768::generate_ml_kem_768_keypair().into_keypair_result() {
                Ok(value) => value,
                Err(_) => return crate::status::CRYPTO_INTERNAL_ERROR,
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &secret) }
    })
}

/// Derives an ML-KEM-768 keypair from a caller-supplied 64-byte FIPS seed.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_kem_768_generate_keypair_from_seed(
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
        let secret_key = match <&[u8; ML_KEM_768_SECRET_KEY_LEN]>::try_from(secret_key) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let (public, secret) =
            match crypto_ml_kem_768::generate_ml_kem_768_keypair_from_seed(secret_key) {
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

/// Encapsulates to the ML-KEM-768 `public_key`, writing the 1088-byte
/// ciphertext to `ciphertext_out` and the derived 32-byte shared secret to
/// `shared_secret_out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `ciphertext_out` must point to at least
/// `ciphertext_out_len` writable bytes (at least 1088) and `shared_secret_out`
/// to at least `shared_secret_out_len` writable bytes (at least 32); both must
/// be non-null. Returns [`CryptoStatus`] via the return value: [`CRYPTO_OK`]
/// on success, or [`CRYPTO_INVALID_KEY`] for an invalid public key. The caller
/// owns the secret copy in `shared_secret_out` and must zeroize it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_kem_768_encapsulate(
    public_key: *const u8,
    public_key_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    shared_secret_out: *mut u8,
    shared_secret_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status = validate_disjoint_output_pair(
            ciphertext_out,
            ciphertext_out_len,
            shared_secret_out,
            shared_secret_out_len,
        );
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        // `shared_secret` is `Zeroizing<Vec<u8>>`: the Rust-side buffer is wiped
        // on drop after the copy out. The caller owns the copy written to
        // `shared_secret_out` and is responsible for zeroizing it after use.
        let (ciphertext, shared_secret) =
            match crypto_ml_kem_768::ml_kem_768_encapsulate(public_key) {
                Ok(value) => value,
                Err(_) => return CRYPTO_INVALID_KEY,
            };
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, &ciphertext) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &shared_secret) }
    })
}

/// Deterministically encapsulates to an ML-KEM-768 public key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_kem_768_encapsulate_derand(
    public_key: *const u8,
    public_key_len: usize,
    randomness: *const u8,
    randomness_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    shared_secret_out: *mut u8,
    shared_secret_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status = validate_disjoint_output_pair(
            ciphertext_out,
            ciphertext_out_len,
            shared_secret_out,
            shared_secret_out_len,
        );
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let public_key = match unsafe { read_slice(public_key, public_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let randomness = match unsafe { read_slice(randomness, randomness_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if randomness.len() != ML_KEM_768_ENCAPS_RANDOMNESS_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let (ciphertext, shared_secret) =
            match crypto_ml_kem_768::ml_kem_768_encapsulate_derand(public_key, randomness) {
                Ok(value) => value,
                Err(_) => return CRYPTO_INVALID_KEY,
            };
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, &ciphertext) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &shared_secret) }
    })
}

/// Decapsulates an ML-KEM-768 `ciphertext` with `secret_key`, writing the
/// recovered 32-byte shared secret to `shared_secret_out`.
///
/// # Safety
///
/// `ciphertext` must be valid for `ciphertext_len` bytes (must be 1088) and
/// `secret_key` for `secret_key_len` bytes (must be 64); a pointer may be null
/// only when its length is `0`. `shared_secret_out` must be non-null and point
/// to at least `shared_secret_out_len` writable bytes (at least 32). Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success,
/// [`CRYPTO_INVALID_KEY`] for a bad secret-key length, or
/// [`CRYPTO_INVALID_CIPHERTEXT`] for a bad ciphertext length or decapsulation
/// error. The caller owns the secret copy in `shared_secret_out` and must
/// zeroize it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_kem_768_decapsulate(
    ciphertext: *const u8,
    ciphertext_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    shared_secret_out: *mut u8,
    shared_secret_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let ciphertext = match unsafe { read_slice(ciphertext, ciphertext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
            return CRYPTO_INVALID_CIPHERTEXT;
        }
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if secret_key.len() != ML_KEM_768_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        // The decapsulated secret is `Zeroizing<Vec<u8>>`: the Rust-side buffer
        // is wiped on drop after the copy out. The caller owns the copy written
        // to `shared_secret_out` and is responsible for zeroizing it after use.
        match crypto_ml_kem_768::ml_kem_768_decapsulate(ciphertext, secret_key) {
            Ok(value) => unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &value) },
            Err(_) => CRYPTO_INVALID_CIPHERTEXT,
        }
    })
}

/// Validates a 1184-byte ML-KEM-768 `public_key` and copies its canonical
/// encoding to `out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 1184; may be
/// null only when the length is `0`). `out` must be non-null and point to at
/// least `out_len` writable bytes (at least 1184). Returns [`CryptoStatus`]
/// via the return value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`]
/// for a bad key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_kem_768_encode_public_key(
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
        if public_key.len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        unsafe { write_fixed(out, out_len, public_key) }
    })
}

/// Validates a 1184-byte encoded ML-KEM-768 `public_key` and copies the
/// decoded raw public key to `out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 1184; may be
/// null only when the length is `0`). `out` must be non-null and point to at
/// least `out_len` writable bytes (at least 1184). Returns [`CryptoStatus`]
/// via the return value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`]
/// for a bad key length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ml_kem_768_decode_public_key(
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
        if public_key.len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        unsafe { write_fixed(out, out_len, public_key) }
    })
}
