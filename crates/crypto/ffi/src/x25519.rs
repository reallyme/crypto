// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::status::{
    CryptoStatus, IntoKeypairResult, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_KEY, CRYPTO_OK,
};

/// Length in bytes of an X25519 public key (32).
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of an X25519 secret key (32).
pub const X25519_SECRET_KEY_LEN: usize = 32;
/// Length in bytes of an X25519 shared secret (32).
pub const X25519_SHARED_SECRET_LEN: usize = 32;

/// Generates an X25519 keypair, writing the 32-byte public key to `public_out`
/// and the 32-byte secret key to `secret_out`.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes (at
/// least 32) and `secret_out` to at least `secret_out_len` writable bytes (at
/// least 32); both must be non-null. Returns [`CryptoStatus`] via the return
/// value: [`CRYPTO_OK`] on success or a negative error code. The caller owns
/// the secret copy in `secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_x25519_generate_keypair(
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
        let (public, secret) = match crypto_x25519::generate_x25519_keypair().into_keypair_result()
        {
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

/// Derives an X25519 keypair from a caller-supplied 32-byte scalar seed.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_x25519_generate_keypair_from_seed(
    seed: *const u8,
    seed_len: usize,
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
        let seed = match unsafe { read_slice(seed, seed_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let seed = match <&[u8; X25519_SECRET_KEY_LEN]>::try_from(seed) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let (public, secret) = crypto_x25519::generate_x25519_keypair_from_seed(seed);
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &secret) }
    })
}

/// Performs X25519 Diffie-Hellman between `secret_key` and `public_key`,
/// writing the 32-byte shared secret to `shared_secret_out`.
///
/// # Safety
///
/// `secret_key` must be valid for `secret_key_len` bytes and `public_key` for
/// `public_key_len` bytes (either may be null only when its length is `0`).
/// `shared_secret_out` must be non-null and point to at least
/// `shared_secret_out_len` writable bytes (at least 32). Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success, or
/// [`CRYPTO_INVALID_KEY`] for an invalid key. The caller owns the secret copy
/// in `shared_secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_x25519_derive_shared_secret(
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
        match crypto_x25519::derive_x25519_shared_secret(secret_key, public_key) {
            Ok(value) => unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Validates a 32-byte X25519 `public_key` and writes it to `out`
/// unchanged.
///
/// An X25519 public key is the raw 32-byte Montgomery u-coordinate, already
/// its canonical encoding, so this is a length check and byte-for-byte copy
/// — it does not transform the key. It exists so every key type presents
/// the same explicit encode/decode surface across the C ABI.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `out` must be non-null and point to at least
/// `out_len` writable bytes (32). Returns [`CryptoStatus`] via the return
/// value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`] for a key that
/// is not exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_x25519_encode_public_key(
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
        match crypto_x25519::encode_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Decodes an encoded X25519 `public_key`, validating it and writing the
/// decoded raw public key to `out`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `out` must be non-null and point to at least
/// `out_len` writable bytes sufficient for the decoded key. Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success, or
/// [`CRYPTO_INVALID_KEY`] for an invalid encoding.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_x25519_decode_public_key(
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
        match crypto_x25519::decode_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}
