// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::signature_status::{key_management_status, sign_status, verify_status};
use crate::status::{
    CryptoStatus, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE, CRYPTO_OK,
};
use crypto_core::Algorithm;
use reallyme_crypto::operations::key_encoding;
use zeroize::Zeroizing;

/// Length in bytes of an SLH-DSA-SHA2-128s public key (32).
pub const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of an SLH-DSA-SHA2-128s serialized secret key (64).
pub const SLH_DSA_SHA2_128S_SECRET_KEY_LEN: usize = 64;
/// Length in bytes of an SLH-DSA-SHA2-128s detached signature (7856).
pub const SLH_DSA_SHA2_128S_SIGNATURE_LEN: usize = 7_856;
/// Length in bytes of each FIPS 205 keygen seed component for SHA2-128s (16).
pub const SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN: usize = 16;
const SLH_DSA_KEYGEN_SEED_PART_COUNT: usize = 3;

/// Generates an SLH-DSA-SHA2-128s keypair.
///
/// # Safety
///
/// `public_out` must point to at least `public_out_len` writable bytes (at
/// least 32) and `secret_key_out` to at least `secret_key_out_len` writable
/// bytes (at least 64); both must be non-null. The caller owns the secret copy
/// written to `secret_key_out` and is responsible for zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_slh_dsa_sha2_128s_generate_keypair(
    public_out: *mut u8,
    public_out_len: usize,
    secret_key_out: *mut u8,
    secret_key_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status = validate_disjoint_output_pair(
            public_out,
            public_out_len,
            secret_key_out,
            secret_key_out_len,
        );
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let key_pair = match reallyme_crypto::operations::signature::generate_key_pair(
            Algorithm::SlhDsaSha2_128s,
        ) {
            Ok(value) => value,
            Err(error) => return key_management_status(error),
        };
        let status = unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_key_out, secret_key_out_len, &key_pair.secret_key) }
    })
}

/// Derives an SLH-DSA-SHA2-128s keypair from FIPS 205 keygen seeds.
///
/// # Safety
///
/// The three seed pointers must each be valid for 16 bytes. Output buffers
/// follow the same contract as [`rm_crypto_slh_dsa_sha2_128s_generate_keypair`].
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_slh_dsa_sha2_128s_derive_keypair(
    sk_seed: *const u8,
    sk_seed_len: usize,
    sk_prf: *const u8,
    sk_prf_len: usize,
    pk_seed: *const u8,
    pk_seed_len: usize,
    public_out: *mut u8,
    public_out_len: usize,
    secret_key_out: *mut u8,
    secret_key_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let output_status = validate_disjoint_output_pair(
            public_out,
            public_out_len,
            secret_key_out,
            secret_key_out_len,
        );
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let sk_seed = match unsafe { read_slice(sk_seed, sk_seed_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let sk_prf = match unsafe { read_slice(sk_prf, sk_prf_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let pk_seed = match unsafe { read_slice(pk_seed, pk_seed_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if sk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
            || sk_prf.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
            || pk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        {
            return CRYPTO_INVALID_KEY;
        }

        let seed_material_capacity =
            match SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN.checked_mul(SLH_DSA_KEYGEN_SEED_PART_COUNT) {
                Some(capacity) => capacity,
                None => return CRYPTO_INTERNAL_ERROR,
            };
        let mut seed_material = Zeroizing::new(Vec::with_capacity(seed_material_capacity));
        seed_material.extend_from_slice(sk_seed);
        seed_material.extend_from_slice(sk_prf);
        seed_material.extend_from_slice(pk_seed);
        let key_pair = match reallyme_crypto::operations::signature::derive_key_pair(
            Algorithm::SlhDsaSha2_128s,
            &seed_material,
        ) {
            Ok(value) => value,
            Err(error) => return key_management_status(error),
        };
        let status = unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_key_out, secret_key_out_len, &key_pair.secret_key) }
    })
}

/// Signs `message` with an SLH-DSA-SHA2-128s serialized secret key.
///
/// # Safety
///
/// `secret_key` must be valid for `secret_key_len` bytes (must be 64),
/// `message` for `message_len` bytes, and `signature_out` must point to at
/// least 7856 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_slh_dsa_sha2_128s_sign(
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
        if secret_key.len() != SLH_DSA_SHA2_128S_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match reallyme_crypto::operations::signature::sign(
            Algorithm::SlhDsaSha2_128s,
            secret_key,
            message,
        ) {
            Ok(signature) => unsafe { write_fixed(signature_out, signature_out_len, &signature) },
            Err(error) => sign_status(error),
        }
    })
}

/// Verifies an SLH-DSA-SHA2-128s detached signature.
///
/// # Safety
///
/// `public_key`, `message`, and `signature` must be valid for their lengths.
/// `valid_out` must be a non-null writable `i32`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_slh_dsa_sha2_128s_verify(
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
        if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN {
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
        if signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_LEN {
            return CRYPTO_INVALID_SIGNATURE;
        }
        match reallyme_crypto::operations::signature::verify(
            Algorithm::SlhDsaSha2_128s,
            public_key,
            message,
            signature,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
        }
    })
}

/// Validates and copies an SLH-DSA-SHA2-128s public key.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes and `out` must point
/// to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_slh_dsa_sha2_128s_encode_public_key(
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
        match key_encoding::copy_fixed_public_key(public_key, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}

/// Validates and copies an encoded SLH-DSA-SHA2-128s public key.
///
/// # Safety
///
/// `public_key` must be valid for `public_key_len` bytes and `out` must point
/// to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_slh_dsa_sha2_128s_decode_public_key(
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
        match key_encoding::copy_fixed_public_key(public_key, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN) {
            Ok(value) => unsafe { write_fixed(out, out_len, &value) },
            Err(_) => CRYPTO_INVALID_KEY,
        }
    })
}
