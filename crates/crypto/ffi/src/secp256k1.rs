// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::status::{
    CryptoStatus, IntoKeypairResult, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK,
};

/// Length in bytes of a secp256k1 secret key (32).
pub const SECP256K1_SECRET_KEY_LEN: usize = 32;
/// Length in bytes of a SEC1 compressed secp256k1 public key (33).
pub const SECP256K1_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
/// Length in bytes of a SEC1 uncompressed secp256k1 public key (65).
pub const SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
/// Length in bytes of a secp256k1 compact (r‖s) ECDSA signature (64).
pub const SECP256K1_SIGNATURE_LEN: usize = 64;
/// Length in bytes of a BIP-340 x-only secp256k1 public key (32).
pub const BIP340_SCHNORR_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of a BIP-340 message digest (32).
pub const BIP340_SCHNORR_MESSAGE_LEN: usize = 32;
/// Length in bytes of BIP-340 auxiliary signing randomness (32).
pub const BIP340_SCHNORR_AUX_RAND_LEN: usize = 32;
/// Length in bytes of a BIP-340 Schnorr signature (64).
pub const BIP340_SCHNORR_SIGNATURE_LEN: usize = 64;

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
        let (public, secret) =
            match crypto_secp256k1::generate_secp256k1_keypair().into_keypair_result() {
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
        let (public, secret) =
            match crypto_secp256k1::generate_secp256k1_keypair_from_secret_key(secret_key) {
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
        match crypto_secp256k1::sign_secp256k1(secret_key, message) {
            Ok(value) => unsafe { write_fixed(signature_out, signature_out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
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
        match crypto_secp256k1::verify_secp256k1(signature, message, public_key) {
            Ok(()) => CRYPTO_OK,
            Err(_) => CRYPTO_INVALID_SIGNATURE,
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
        match crypto_secp256k1::encode_public_key(public_key) {
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
        match crypto_secp256k1::decode_public_key(public_key) {
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
        let (x, y) = match crypto_secp256k1::decompress_public_key(public_key) {
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

/// Derives the BIP-340 x-only public key for a secp256k1 secret scalar.
///
/// # Safety
///
/// `secret_key` must be valid for `secret_key_len` bytes (must be 32) and
/// `public_key_out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_bip340_schnorr_derive_public_key(
    secret_key: *const u8,
    secret_key_len: usize,
    public_key_out: *mut u8,
    public_key_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if secret_key.len() != SECP256K1_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        match crypto_secp256k1::derive_bip340_schnorr_public_key(secret_key) {
            Ok(public_key) => unsafe {
                write_fixed(public_key_out, public_key_out_len, &public_key)
            },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Signs a 32-byte BIP-340 message with explicit 32-byte auxiliary randomness.
///
/// # Safety
///
/// `secret_key`, `message32`, and `aux_rand32` must be valid for their exact
/// lengths. `signature_out` must point to at least 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_bip340_schnorr_sign(
    secret_key: *const u8,
    secret_key_len: usize,
    message32: *const u8,
    message32_len: usize,
    aux_rand32: *const u8,
    aux_rand32_len: usize,
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
        let message32 = match unsafe { read_slice(message32, message32_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let aux_rand32 = match unsafe { read_slice(aux_rand32, aux_rand32_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if message32.len() != BIP340_SCHNORR_MESSAGE_LEN
            || aux_rand32.len() != BIP340_SCHNORR_AUX_RAND_LEN
        {
            return CRYPTO_INVALID_ARGUMENT;
        }
        match crypto_secp256k1::sign_bip340_schnorr(secret_key, message32, aux_rand32) {
            Ok(signature) => unsafe { write_fixed(signature_out, signature_out_len, &signature) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Verifies a BIP-340 Schnorr signature over a 32-byte message.
///
/// # Safety
///
/// `signature`, `message32`, and `public_key_xonly` must be valid for their
/// exact lengths.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_bip340_schnorr_verify(
    signature: *const u8,
    signature_len: usize,
    message32: *const u8,
    message32_len: usize,
    public_key_xonly: *const u8,
    public_key_xonly_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let signature = match unsafe { read_slice(signature, signature_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if signature.len() != BIP340_SCHNORR_SIGNATURE_LEN {
            return CRYPTO_INVALID_SIGNATURE;
        }
        let message32 = match unsafe { read_slice(message32, message32_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if message32.len() != BIP340_SCHNORR_MESSAGE_LEN {
            return CRYPTO_INVALID_ARGUMENT;
        }
        let public_key_xonly = match unsafe { read_slice(public_key_xonly, public_key_xonly_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if public_key_xonly.len() != BIP340_SCHNORR_PUBLIC_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        match crypto_secp256k1::verify_bip340_schnorr(signature, message32, public_key_xonly) {
            Ok(()) => CRYPTO_OK,
            Err(_) => CRYPTO_INVALID_SIGNATURE,
        }
    })
}

/// Validates and copies a BIP-340 x-only public key.
///
/// # Safety
///
/// `public_key_xonly` must be valid for `public_key_xonly_len` bytes and `out`
/// must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_bip340_schnorr_encode_public_key(
    public_key_xonly: *const u8,
    public_key_xonly_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key_xonly = match unsafe { read_slice(public_key_xonly, public_key_xonly_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match crypto_secp256k1::encode_bip340_schnorr_public_key(public_key_xonly) {
            Ok(public_key) => unsafe { write_fixed(out, out_len, &public_key) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Validates and copies an encoded BIP-340 x-only public key.
///
/// # Safety
///
/// `public_key_xonly` must be valid for `public_key_xonly_len` bytes and `out`
/// must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_bip340_schnorr_decode_public_key(
    public_key_xonly: *const u8,
    public_key_xonly_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key_xonly = match unsafe { read_slice(public_key_xonly, public_key_xonly_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match crypto_secp256k1::decode_bip340_schnorr_public_key(public_key_xonly) {
            Ok(public_key) => unsafe { write_fixed(out, out_len, &public_key) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}
