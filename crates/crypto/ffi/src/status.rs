// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Signed 32-bit status code returned by C ABI entry points
/// (`rm_crypto_status_t` in the C header).
///
/// Most functions return `0` on success and negative values for failures.
/// Protobuf result-envelope entry points may return positive status values
/// when the byte output is valid structured error data rather than a successful
/// result message.
pub type CryptoStatus = i32;

/// Operation succeeded (`0`).
pub const CRYPTO_OK: CryptoStatus = 0;
/// Operation returned structured `CryptoError` protobuf bytes instead of result bytes (`1`).
pub const CRYPTO_PROTO_ERROR: CryptoStatus = 1;
/// A pointer/length argument was invalid, null where required, or malformed (`-1`).
pub const CRYPTO_INVALID_ARGUMENT: CryptoStatus = -1;
/// A supplied key had the wrong length or otherwise failed validation (`-2`).
pub const CRYPTO_INVALID_KEY: CryptoStatus = -2;
/// The signature was structurally invalid or did not verify (`-3`).
pub const CRYPTO_INVALID_SIGNATURE: CryptoStatus = -3;
/// The ciphertext was malformed or had an invalid length (`-4`).
pub const CRYPTO_INVALID_CIPHERTEXT: CryptoStatus = -4;
/// The caller-provided output buffer was too small for the result (`-5`).
pub const CRYPTO_BUFFER_TOO_SMALL: CryptoStatus = -5;
/// AEAD tag verification (decryption authentication) failed (`-6`).
pub const CRYPTO_AUTHENTICATION_FAILED: CryptoStatus = -6;
/// An unexpected internal failure, including a caught panic (`-128`).
pub const CRYPTO_INTERNAL_ERROR: CryptoStatus = -128;

use zeroize::Zeroizing;

/// Normalized keypair shape crossing the FFI helpers:
/// (public_key, secret_key). The secret half zeroizes on drop.
pub type KeypairBuffers = (Vec<u8>, Zeroizing<Vec<u8>>);

/// Normalizes the various keypair-generation return shapes into a common
/// `Result<KeypairBuffers, CryptoStatus>` for the FFI layer.
pub trait IntoKeypairResult {
    /// Converts `self` into the normalized keypair result, mapping any
    /// underlying error to [`CRYPTO_INTERNAL_ERROR`].
    fn into_keypair_result(self) -> Result<KeypairBuffers, CryptoStatus>;
}

impl IntoKeypairResult for KeypairBuffers {
    fn into_keypair_result(self) -> Result<KeypairBuffers, CryptoStatus> {
        Ok(self)
    }
}

impl<E> IntoKeypairResult for Result<KeypairBuffers, E> {
    fn into_keypair_result(self) -> Result<KeypairBuffers, CryptoStatus> {
        self.map_err(|_| CRYPTO_INTERNAL_ERROR)
    }
}
