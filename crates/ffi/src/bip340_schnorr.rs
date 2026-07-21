// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::signature_status::{key_management_status, verify_status};
use crate::status::{
    CryptoStatus, CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK,
};
use reallyme_crypto::operations::key_encoding;

/// Length in bytes of a secp256k1 secret key (32).
pub const SECP256K1_SECRET_KEY_LEN: usize = 32;
/// Length in bytes of a BIP-340 x-only secp256k1 public key (32).
pub const BIP340_SCHNORR_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of a BIP-340 message digest (32).
pub const BIP340_SCHNORR_MESSAGE_LEN: usize = 32;
/// Length in bytes of BIP-340 auxiliary signing randomness (32).
pub const BIP340_SCHNORR_AUX_RAND_LEN: usize = 32;
/// Length in bytes of a BIP-340 Schnorr signature (64).
pub const BIP340_SCHNORR_SIGNATURE_LEN: usize = 64;

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
        match reallyme_crypto::operations::signature::derive_bip340_public_key(secret_key) {
            Ok(public_key) => unsafe {
                write_fixed(public_key_out, public_key_out_len, &public_key)
            },
            Err(error) => key_management_status(error),
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
        match reallyme_crypto::operations::signature::sign_bip340(secret_key, message32, aux_rand32)
        {
            Ok(signature) => unsafe { write_fixed(signature_out, signature_out_len, &signature) },
            Err(error) => bip340_sign_status(error),
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
        match reallyme_crypto::operations::signature::verify_bip340(
            signature,
            message32,
            public_key_xonly,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
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
        match key_encoding::encode_bip340_schnorr_public_key(public_key_xonly) {
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
        match key_encoding::decode_bip340_schnorr_public_key(public_key_xonly) {
            Ok(public_key) => unsafe { write_fixed(out, out_len, &public_key) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

fn bip340_sign_status(error: reallyme_crypto::operations::OperationError) -> CryptoStatus {
    match error {
        reallyme_crypto::operations::OperationError::Primitive {
            reason: reallyme_crypto::operations::PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        reallyme_crypto::operations::OperationError::Primitive {
            reason: reallyme_crypto::operations::PrimitiveErrorReason::InvalidLength,
        }
        | reallyme_crypto::operations::OperationError::Primitive {
            reason: reallyme_crypto::operations::PrimitiveErrorReason::LengthOverflow,
        } => CRYPTO_INVALID_ARGUMENT,
        reallyme_crypto::operations::OperationError::Primitive {
            reason: reallyme_crypto::operations::PrimitiveErrorReason::VerificationFailed,
        } => CRYPTO_INVALID_SIGNATURE,
        _ => crate::signature_status::sign_status(error),
    }
}
