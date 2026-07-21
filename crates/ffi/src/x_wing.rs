// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::Algorithm;
use reallyme_crypto::operations::key_encoding;
use reallyme_crypto::x_wing as crypto_x_wing;

use crate::guard::ffi_guard;
use crate::kem_status::{
    kem_decapsulation_status, kem_encapsulation_status, kem_key_management_status,
};
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::status::{CryptoStatus, CRYPTO_INVALID_KEY, CRYPTO_OK};

/// Length in bytes of an X-Wing-768 public key.
pub const X_WING_768_PUBLIC_KEY_LEN: usize = crypto_x_wing::X_WING_768_PUBLIC_KEY_LEN;
/// Length in bytes of an X-Wing-768 ciphertext.
pub const X_WING_768_CIPHERTEXT_LEN: usize = crypto_x_wing::X_WING_768_CIPHERTEXT_LEN;
/// Length in bytes of an X-Wing private seed.
pub const X_WING_SECRET_KEY_LEN: usize = crypto_x_wing::X_WING_SECRET_KEY_LEN;
/// Length in bytes of an X-Wing deterministic encapsulation seed.
pub const X_WING_ENCAPS_SEED_LEN: usize = crypto_x_wing::X_WING_ENCAPS_SEED_LEN;
/// Length in bytes of an X-Wing shared secret.
pub const X_WING_SHARED_SECRET_LEN: usize = crypto_x_wing::X_WING_SHARED_SECRET_LEN;

#[no_mangle]
/// Generates an X-Wing-768 keypair.
pub unsafe extern "C" fn rm_crypto_x_wing_768_generate_keypair(
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
        let key_pair =
            match reallyme_crypto::operations::kem::generate_key_pair(Algorithm::XWing768) {
                Ok(value) => value,
                Err(error) => return kem_key_management_status(error),
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &key_pair.secret_key) }
    })
}

#[no_mangle]
/// Derives an X-Wing-768 public key from a 32-byte private seed.
pub unsafe extern "C" fn rm_crypto_x_wing_768_generate_keypair_derand(
    secret_key: *const u8,
    secret_key_len: usize,
    public_out: *mut u8,
    public_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let key_pair = match reallyme_crypto::operations::kem::derive_key_pair(
            Algorithm::XWing768,
            secret_key,
        ) {
            Ok(value) => value,
            Err(error) => return kem_key_management_status(error),
        };
        unsafe { write_fixed(public_out, public_out_len, &key_pair.public_key) }
    })
}

#[no_mangle]
/// Encapsulates a shared secret to an X-Wing-768 public key.
pub unsafe extern "C" fn rm_crypto_x_wing_768_encapsulate(
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
        let encapsulation =
            match reallyme_crypto::operations::kem::encapsulate(Algorithm::XWing768, public_key) {
                Ok(value) => value,
                Err(error) => return kem_encapsulation_status(error),
            };
        write_encapsulation(
            encapsulation,
            ciphertext_out,
            ciphertext_out_len,
            shared_secret_out,
            shared_secret_out_len,
        )
    })
}

#[no_mangle]
/// Deterministically encapsulates to an X-Wing-768 public key for conformance vectors.
#[cfg(feature = "test-vectors")]
pub unsafe extern "C" fn rm_crypto_x_wing_768_encapsulate_derand(
    public_key: *const u8,
    public_key_len: usize,
    seed: *const u8,
    seed_len: usize,
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
        let seed = match unsafe { read_slice(seed, seed_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let encapsulation = match reallyme_crypto::operations::kem::encapsulate_derand(
            Algorithm::XWing768,
            public_key,
            seed,
        ) {
            Ok(value) => value,
            Err(error) => return kem_encapsulation_status(error),
        };
        write_encapsulation(
            encapsulation,
            ciphertext_out,
            ciphertext_out_len,
            shared_secret_out,
            shared_secret_out_len,
        )
    })
}

#[no_mangle]
/// Decapsulates an X-Wing-768 ciphertext with a 32-byte private seed.
pub unsafe extern "C" fn rm_crypto_x_wing_768_decapsulate(
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
        let secret_key = match unsafe { read_slice(secret_key, secret_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let shared_secret = match reallyme_crypto::operations::kem::decapsulate(
            Algorithm::XWing768,
            ciphertext,
            secret_key,
        ) {
            Ok(value) => value,
            Err(error) => return kem_decapsulation_status(error),
        };
        unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &shared_secret) }
    })
}

#[no_mangle]
/// Validates and copies an X-Wing-768 public key.
pub unsafe extern "C" fn rm_crypto_x_wing_768_encode_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| unsafe { copy_x_wing_768_public_key(public_key, public_key_len, out, out_len) })
}

#[no_mangle]
/// Validates and copies an encoded X-Wing-768 public key.
pub unsafe extern "C" fn rm_crypto_x_wing_768_decode_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| unsafe { copy_x_wing_768_public_key(public_key, public_key_len, out, out_len) })
}

fn write_encapsulation(
    encapsulation: reallyme_crypto::operations::kem::KemEncapsulation,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    shared_secret_out: *mut u8,
    shared_secret_out_len: usize,
) -> CryptoStatus {
    let status = unsafe {
        write_fixed(
            ciphertext_out,
            ciphertext_out_len,
            &encapsulation.ciphertext,
        )
    };
    if status != CRYPTO_OK {
        return status;
    }
    unsafe {
        write_fixed(
            shared_secret_out,
            shared_secret_out_len,
            &encapsulation.shared_secret,
        )
    }
}

unsafe fn copy_x_wing_768_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    let public_key = match unsafe { read_slice(public_key, public_key_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    match key_encoding::copy_fixed_public_key(public_key, X_WING_768_PUBLIC_KEY_LEN) {
        Ok(value) => unsafe { write_fixed(out, out_len, &value) },
        Err(_) => CRYPTO_INVALID_KEY,
    }
}
