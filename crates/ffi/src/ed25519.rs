// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::signature_status::{key_management_status, sign_status, verify_status};
use crate::status::{CryptoStatus, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK};
use crypto_core::Algorithm;
use reallyme_crypto::operations::key_encoding;

/// Length in bytes of an Ed25519 public key (32).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of an Ed25519 secret-key seed (32).
pub const ED25519_SECRET_KEY_LEN: usize = 32;
/// Length in bytes of an Ed25519 signature (64).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Generates an Ed25519 keypair, writing the 32-byte public key to
/// `public_out` and the 32-byte secret key to `secret_out`.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes (at
/// least 32) and `secret_out` to at least `secret_out_len` writable bytes (at
/// least 32); both must be non-null. Returns [`CryptoStatus`] via the return
/// value: [`CRYPTO_OK`] on success or a negative error code. The caller owns
/// the secret copy in `secret_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ed25519_generate_keypair(
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
            match reallyme_crypto::operations::signature::generate_key_pair(Algorithm::Ed25519) {
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

/// Derives an Ed25519 keypair from a caller-supplied 32-byte seed.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ed25519_generate_keypair_from_seed(
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
        let seed = match <&[u8; ED25519_SECRET_KEY_LEN]>::try_from(seed) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        let key_pair =
            match reallyme_crypto::operations::signature::derive_key_pair(Algorithm::Ed25519, seed)
            {
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

/// Signs `message` with the Ed25519 `secret` key, writing the 64-byte
/// signature to `signature_out`. The secret must be a 32-byte seed.
///
/// # Safety
///
/// `secret` must be valid for `secret_len` bytes and `message` for
/// `message_len` bytes (either may be null only when its length is `0`).
/// `signature_out` must be non-null and point to at least `signature_out_len`
/// writable bytes (at least 64). Returns [`CryptoStatus`] via the return value:
/// [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`] for a bad secret length
/// or key.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ed25519_sign(
    secret: *const u8,
    secret_len: usize,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
    signature_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let secret = match unsafe { read_slice(secret, secret_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if secret.len() != ED25519_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match reallyme_crypto::operations::signature::sign(Algorithm::Ed25519, secret, message) {
            Ok(signature) => unsafe { write_fixed(signature_out, signature_out_len, &signature) },
            Err(error) => sign_status(error),
        }
    })
}

/// Verifies an Ed25519 `signature` over `message` against `public_key`.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (must be 32),
/// `message` for `message_len` bytes, and `signature` for `signature_len`
/// bytes (must be 64); a pointer may be null only when its length is `0`.
/// Returns [`CRYPTO_OK`] only when the signature is valid.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ed25519_verify(
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
        if public_key.len() != ED25519_PUBLIC_KEY_LEN {
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
        if signature.len() != ED25519_SIGNATURE_LEN {
            return CRYPTO_INVALID_SIGNATURE;
        }
        match reallyme_crypto::operations::signature::verify(
            Algorithm::Ed25519,
            public_key,
            message,
            signature,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
        }
    })
}

/// Validates a 32-byte Ed25519 `public_key` and writes it to `out`
/// unchanged.
///
/// An Ed25519 public key is a compressed Edwards point that is already its
/// own canonical 32-byte encoding, so this performs a length check and a
/// byte-for-byte copy — it does not transform the key. It exists so every
/// key type presents the same explicit encode/decode surface across the C
/// ABI.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `out` must be non-null and point to at least
/// `out_len` writable bytes (32). Returns [`CryptoStatus`] via the return
/// value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`] for a key that
/// is not exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ed25519_encode_public_key(
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
        match key_encoding::encode_ed25519_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Validates an encoded Ed25519 `public_key` and writes the raw 32-byte key
/// to `out`.
///
/// The Ed25519 encoding is the raw 32-byte key, so decoding is a length
/// check plus a byte-for-byte copy — the inverse of
/// [`rm_crypto_ed25519_encode_public_key`] and, for this key type,
/// identical to it.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes (may be null only
/// when `public_key_len == 0`). `out` must be non-null and point to at least
/// `out_len` writable bytes (32). Returns [`CryptoStatus`] via the return
/// value: [`CRYPTO_OK`] on success, or [`CRYPTO_INVALID_KEY`] for a key that
/// is not exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_ed25519_decode_public_key(
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
        match key_encoding::decode_ed25519_public_key(public_key) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}
