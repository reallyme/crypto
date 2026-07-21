// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::read_slice;
use crate::signature_status::verify_status;
use crate::status::{CryptoStatus, CRYPTO_INVALID_ARGUMENT, CRYPTO_OK};
use reallyme_crypto::rsa as crypto_rsa;

/// FFI suite identifier for historical RSA/SHA-1 document verification.
pub const RSA_HASH_SHA1: u32 = crypto_rsa::RsaHash::Sha1.ffi_id();
/// FFI suite identifier for RSA/SHA-256 verification.
pub const RSA_HASH_SHA256: u32 = crypto_rsa::RsaHash::Sha256.ffi_id();
/// FFI suite identifier for RSA/SHA-384 verification.
pub const RSA_HASH_SHA384: u32 = crypto_rsa::RsaHash::Sha384.ffi_id();
/// FFI suite identifier for RSA/SHA-512 verification.
pub const RSA_HASH_SHA512: u32 = crypto_rsa::RsaHash::Sha512.ffi_id();

/// FFI public-key encoding identifier for PKCS#1 `RSAPublicKey` DER.
pub const RSA_PUBLIC_KEY_ENCODING_PKCS1_DER: u32 =
    crypto_rsa::RsaPublicKeyDerEncoding::Pkcs1.ffi_id();
/// FFI public-key encoding identifier for X.509 SPKI DER.
pub const RSA_PUBLIC_KEY_ENCODING_SPKI_DER: u32 =
    crypto_rsa::RsaPublicKeyDerEncoding::Spki.ffi_id();

/// Verifies an RSASSA-PKCS1-v1_5 signature.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_rsa_verify_pkcs1v15(
    public_key_der: *const u8,
    public_key_der_len: usize,
    public_key_encoding: u32,
    hash_suite: u32,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key_der = match unsafe { read_slice(public_key_der, public_key_der_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let signature = match unsafe { read_slice(signature, signature_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let encoding = match crypto_rsa::RsaPublicKeyDerEncoding::from_ffi_id(public_key_encoding) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        let hash = match crypto_rsa::RsaHash::from_ffi_id(hash_suite) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        match reallyme_crypto::operations::signature::verify_rsa_pkcs1v15(
            public_key_der,
            encoding,
            hash,
            message,
            signature,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
        }
    })
}

/// Verifies an RSASSA-PSS signature.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_rsa_verify_pss(
    public_key_der: *const u8,
    public_key_der_len: usize,
    public_key_encoding: u32,
    message_hash_suite: u32,
    mgf1_hash_suite: u32,
    salt_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let public_key_der = match unsafe { read_slice(public_key_der, public_key_der_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let message = match unsafe { read_slice(message, message_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let signature = match unsafe { read_slice(signature, signature_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let encoding = match crypto_rsa::RsaPublicKeyDerEncoding::from_ffi_id(public_key_encoding) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        let message_hash = match crypto_rsa::RsaHash::from_ffi_id(message_hash_suite) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        let mgf1_hash = match crypto_rsa::RsaHash::from_ffi_id(mgf1_hash_suite) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        let params = crypto_rsa::RsaPssParams {
            message_hash,
            mgf1_hash,
            salt_len,
        };
        match reallyme_crypto::operations::signature::verify_rsa_pss(
            public_key_der,
            encoding,
            params,
            message,
            signature,
        ) {
            Ok(()) => CRYPTO_OK,
            Err(error) => verify_status(error),
        }
    })
}
