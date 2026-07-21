// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

use super::{
    AeadBackend, AeadFailureKind, ConstantTimeFailureKind, HkdfFailureKind, HkdfHash, KdfAlgorithm,
    KdfFailureKind, KdfProfile, KemFailureKind, KeyAgreementFailureKind, KeyWrapAlgorithm,
    KeyWrapFailureKind, KeyWrapOperation, MacFailureKind, MacHash, RngFailureKind, RngOutputKind,
    SignatureBackend, SignatureFailureKind, SignatureOperation,
};

/// Typed error taxonomy for all crypto operations in the workspace.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Supplied key material was malformed or otherwise invalid.
    #[error("invalid key material")]
    InvalidKey,

    /// An AEAD key did not have the length the cipher requires.
    #[error("invalid AEAD key length: expected {expected} bytes, got {actual} bytes")]
    InvalidAeadKeyLength {
        /// Key length in bytes the cipher requires.
        expected: usize,
        /// Key length in bytes that was supplied.
        actual: usize,
    },

    /// An AEAD nonce did not have the length the cipher requires.
    #[error("invalid AEAD nonce length: expected {expected} bytes, got {actual} bytes")]
    InvalidAeadNonceLength {
        /// Nonce length in bytes the cipher requires.
        expected: usize,
        /// Nonce length in bytes that was supplied.
        actual: usize,
    },

    /// A ciphertext was shorter than the minimum (tag) length.
    #[error("invalid ciphertext length: minimum {minimum} bytes, got {actual} bytes")]
    InvalidCiphertextLength {
        /// Minimum ciphertext length in bytes (the authentication tag length).
        minimum: usize,
        /// Ciphertext length in bytes that was supplied.
        actual: usize,
    },

    /// AEAD encryption failed in the given backend for the given reason.
    #[error("AEAD encryption failed in {backend} backend: {kind}")]
    AeadEncrypt {
        /// Backend lane in which the failure occurred.
        backend: AeadBackend,
        /// Specific encryption failure cause.
        kind: AeadFailureKind,
    },

    /// AEAD decryption failed in the given backend for the given reason.
    #[error("AEAD decryption failed in {backend} backend: {kind}")]
    AeadDecrypt {
        /// Backend lane in which the failure occurred.
        backend: AeadBackend,
        /// Specific decryption failure cause (includes authentication failure).
        kind: AeadFailureKind,
    },

    /// A signature operation failed in the given backend for the given reason.
    #[error("signature failed in {backend} backend during {operation}: {kind}")]
    Signature {
        /// Backend lane in which the failure occurred.
        backend: SignatureBackend,
        /// Operation (sign, verify, keygen, encode) that failed.
        operation: SignatureOperation,
        /// Specific signature failure cause.
        kind: SignatureFailureKind,
    },

    /// A key agreement operation failed for the given reason.
    #[error("key agreement failed: {kind}")]
    KeyAgreementFailure {
        /// Specific key-agreement failure cause.
        kind: KeyAgreementFailureKind,
    },

    /// A KEM (key encapsulation) operation failed for the given reason.
    #[error("KEM operation failed: {kind}")]
    KemFailure {
        /// Specific KEM failure cause.
        kind: KemFailureKind,
    },

    /// A key-wrap operation failed for the given algorithm and reason.
    #[error("key wrap failed for {algorithm} during {operation}: {kind}")]
    KeyWrap {
        /// Key-wrap algorithm that failed.
        algorithm: KeyWrapAlgorithm,
        /// Operation (wrap or unwrap) that failed.
        operation: KeyWrapOperation,
        /// Specific key-wrap failure cause.
        kind: KeyWrapFailureKind,
    },

    /// A password-based KDF operation failed for the given algorithm/profile.
    #[error("KDF failed for {algorithm}/{profile}: {kind}")]
    Kdf {
        /// KDF algorithm that failed.
        algorithm: KdfAlgorithm,
        /// Cost profile in effect at the time of failure.
        profile: KdfProfile,
        /// Specific KDF failure cause.
        kind: KdfFailureKind,
    },

    /// An HKDF operation failed for the given hash and reason.
    #[error("HKDF failed for {hash}: {kind}")]
    Hkdf {
        /// Hash suite underlying the HKDF operation.
        hash: HkdfHash,
        /// Specific HKDF failure cause.
        kind: HkdfFailureKind,
    },

    /// An HMAC operation failed for the given hash and reason.
    #[error("HMAC failed for {hash}: {kind}")]
    Mac {
        /// Hash suite underlying the HMAC operation.
        hash: MacHash,
        /// Specific HMAC failure cause.
        kind: MacFailureKind,
    },

    /// Secure random generation failed for the given output purpose.
    #[error("secure random generation failed for {output}: {kind}")]
    Rng {
        /// Purpose the requested random bytes were being generated for.
        output: RngOutputKind,
        /// Specific RNG failure cause.
        kind: RngFailureKind,
    },

    /// A constant-time comparison did not match, with the two input lengths.
    #[error("constant-time comparison failed: {kind}")]
    ConstantTimeComparison {
        /// Specific comparison failure cause.
        kind: ConstantTimeFailureKind,
        /// Length in bytes of the left-hand input.
        left_len: usize,
        /// Length in bytes of the right-hand input.
        right_len: usize,
    },

    /// The requested operation is not supported.
    #[error("unsupported operation")]
    Unsupported,
}
