// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_disjoint_output_pair, write_fixed};
use crate::status::{
    CryptoStatus, IntoKeypairResult, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};

/// Length in bytes of an X-Wing-768 public key.
pub const X_WING_768_PUBLIC_KEY_LEN: usize = crypto_x_wing::X_WING_768_PUBLIC_KEY_LEN;
/// Length in bytes of an X-Wing-768 ciphertext.
pub const X_WING_768_CIPHERTEXT_LEN: usize = crypto_x_wing::X_WING_768_CIPHERTEXT_LEN;
/// Length in bytes of an X-Wing-1024 public key.
pub const X_WING_1024_PUBLIC_KEY_LEN: usize = crypto_x_wing::X_WING_1024_PUBLIC_KEY_LEN;
/// Length in bytes of an X-Wing-1024 ciphertext.
pub const X_WING_1024_CIPHERTEXT_LEN: usize = crypto_x_wing::X_WING_1024_CIPHERTEXT_LEN;
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
        let (public, secret) =
            match crypto_x_wing::generate_x_wing_768_keypair().into_keypair_result() {
                Ok(value) => value,
                Err(status) => return status,
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &secret) }
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
        let (public, _secret) = match crypto_x_wing::generate_x_wing_768_keypair_derand(secret_key)
        {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        unsafe { write_fixed(public_out, public_out_len, &public) }
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
        let (ciphertext, shared_secret) = match crypto_x_wing::x_wing_768_encapsulate(public_key) {
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

#[no_mangle]
/// Deterministically encapsulates to an X-Wing-768 public key for conformance vectors.
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
        let (ciphertext, shared_secret) =
            match crypto_x_wing::x_wing_768_encapsulate_derand(public_key, seed) {
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
        if secret_key.len() != X_WING_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        match crypto_x_wing::x_wing_768_decapsulate(ciphertext, secret_key) {
            Ok(value) => unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &value) },
            Err(_) => CRYPTO_INVALID_CIPHERTEXT,
        }
    })
}

#[no_mangle]
/// Generates an X-Wing-1024 keypair.
pub unsafe extern "C" fn rm_crypto_x_wing_1024_generate_keypair(
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
        let (public, secret) =
            match crypto_x_wing::generate_x_wing_1024_keypair().into_keypair_result() {
                Ok(value) => value,
                Err(status) => return status,
            };
        let status = unsafe { write_fixed(public_out, public_out_len, &public) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_fixed(secret_out, secret_out_len, &secret) }
    })
}

#[no_mangle]
/// Derives an X-Wing-1024 public key from a 32-byte private seed.
pub unsafe extern "C" fn rm_crypto_x_wing_1024_generate_keypair_derand(
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
        let (public, _secret) = match crypto_x_wing::generate_x_wing_1024_keypair_derand(secret_key)
        {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_KEY,
        };
        unsafe { write_fixed(public_out, public_out_len, &public) }
    })
}

#[no_mangle]
/// Encapsulates a shared secret to an X-Wing-1024 public key.
pub unsafe extern "C" fn rm_crypto_x_wing_1024_encapsulate(
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
        let (ciphertext, shared_secret) = match crypto_x_wing::x_wing_1024_encapsulate(public_key) {
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

#[no_mangle]
/// Deterministically encapsulates to an X-Wing-1024 public key for conformance vectors.
pub unsafe extern "C" fn rm_crypto_x_wing_1024_encapsulate_derand(
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
        let (ciphertext, shared_secret) =
            match crypto_x_wing::x_wing_1024_encapsulate_derand(public_key, seed) {
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

#[no_mangle]
/// Decapsulates an X-Wing-1024 ciphertext with a 32-byte private seed.
pub unsafe extern "C" fn rm_crypto_x_wing_1024_decapsulate(
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
        if secret_key.len() != X_WING_SECRET_KEY_LEN {
            return CRYPTO_INVALID_KEY;
        }
        match crypto_x_wing::x_wing_1024_decapsulate(ciphertext, secret_key) {
            Ok(value) => unsafe { write_fixed(shared_secret_out, shared_secret_out_len, &value) },
            Err(_) => CRYPTO_INVALID_CIPHERTEXT,
        }
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

#[no_mangle]
/// Validates and copies an X-Wing-1024 public key.
pub unsafe extern "C" fn rm_crypto_x_wing_1024_encode_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| unsafe { copy_x_wing_1024_public_key(public_key, public_key_len, out, out_len) })
}

#[no_mangle]
/// Validates and copies an encoded X-Wing-1024 public key.
pub unsafe extern "C" fn rm_crypto_x_wing_1024_decode_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| unsafe { copy_x_wing_1024_public_key(public_key, public_key_len, out, out_len) })
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
    if public_key.len() != X_WING_768_PUBLIC_KEY_LEN {
        return CRYPTO_INVALID_KEY;
    }
    unsafe { write_fixed(out, out_len, public_key) }
}

unsafe fn copy_x_wing_1024_public_key(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> CryptoStatus {
    let public_key = match unsafe { read_slice(public_key, public_key_len) } {
        Ok(value) => value,
        Err(status) => return status,
    };
    if public_key.len() != X_WING_1024_PUBLIC_KEY_LEN {
        return CRYPTO_INVALID_KEY;
    }
    unsafe { write_fixed(out, out_len, public_key) }
}
