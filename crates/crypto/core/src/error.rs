// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Backend implementation that performed an AEAD operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadBackend {
    /// Pure-Rust native backend.
    Native,
    /// Swift/Apple platform backend.
    Swift,
    /// WebAssembly backend.
    Wasm,
    /// Kotlin/Android platform backend.
    Kotlin,
}

impl core::fmt::Display for AeadBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            AeadBackend::Native => "native",
            AeadBackend::Swift => "swift",
            AeadBackend::Wasm => "wasm",
            AeadBackend::Kotlin => "kotlin",
        };
        write!(f, "{name}")
    }
}

/// Specific reason an AEAD encrypt or decrypt operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadFailureKind {
    /// The supplied key material was not valid for the cipher.
    InvalidKeyMaterial,
    /// An input length exceeded the representable range.
    LengthOverflow,
    /// The ciphertext was shorter than the authentication tag.
    ShortCiphertext,
    /// The backend returned an output of unexpected length.
    InvalidOutputLength,
    /// Tag verification failed (ciphertext or AAD tampered/wrong key).
    AuthenticationFailed,
    /// The backend reported an unspecified internal failure.
    BackendFailure,
}

impl core::fmt::Display for AeadFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            AeadFailureKind::InvalidKeyMaterial => "invalid key material",
            AeadFailureKind::LengthOverflow => "length overflow",
            AeadFailureKind::ShortCiphertext => "ciphertext shorter than tag",
            AeadFailureKind::InvalidOutputLength => "backend returned invalid output length",
            AeadFailureKind::AuthenticationFailed => "authentication failed",
            AeadFailureKind::BackendFailure => "backend failure",
        };
        write!(f, "{detail}")
    }
}

/// Backend implementation that performed a signature operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureBackend {
    /// Pure-Rust native backend.
    Native,
    /// Swift/Apple platform backend.
    Swift,
    /// WebAssembly backend.
    Wasm,
    /// Kotlin/Android platform backend.
    Kotlin,
    /// Apple Secure Enclave hardware-backed backend.
    SecureEnclave,
}

impl core::fmt::Display for SignatureBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            SignatureBackend::Native => "native",
            SignatureBackend::Swift => "swift",
            SignatureBackend::Wasm => "wasm",
            SignatureBackend::Kotlin => "kotlin",
            SignatureBackend::SecureEnclave => "secure_enclave",
        };
        write!(f, "{name}")
    }
}

/// Signature-related operation being attempted when a failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureOperation {
    /// Producing a signature over a message.
    Sign,
    /// Verifying a signature against a message.
    Verify,
    /// Key generation, import, or other key management.
    KeyManagement,
}

impl core::fmt::Display for SignatureOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let op = match self {
            SignatureOperation::Sign => "sign",
            SignatureOperation::Verify => "verify",
            SignatureOperation::KeyManagement => "key_management",
        };
        write!(f, "{op}")
    }
}

/// Specific reason a signature operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFailureKind {
    /// The backend reported an unspecified internal failure.
    BackendFailure,
    /// The supplied private key was malformed or invalid.
    InvalidPrivateKey,
    /// The supplied public key was malformed or invalid.
    InvalidPublicKey,
    /// The signature was malformed or failed verification.
    InvalidSignature,
    /// The message input was invalid for the operation.
    InvalidMessage,
    /// Key generation did not succeed.
    KeyGenerationFailed,
    /// The Secure Enclave was not available on this device.
    SecureEnclaveUnavailable,
    /// The Secure Enclave rejected the supplied key.
    SecureEnclaveRejectedKey,
}

impl core::fmt::Display for SignatureFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            SignatureFailureKind::BackendFailure => "backend failure",
            SignatureFailureKind::InvalidPrivateKey => "invalid private key",
            SignatureFailureKind::InvalidPublicKey => "invalid public key",
            SignatureFailureKind::InvalidSignature => "invalid signature",
            SignatureFailureKind::InvalidMessage => "invalid message",
            SignatureFailureKind::KeyGenerationFailed => "key generation failed",
            SignatureFailureKind::SecureEnclaveUnavailable => "secure enclave unavailable",
            SignatureFailureKind::SecureEnclaveRejectedKey => "secure enclave rejected key",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a key agreement operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAgreementFailureKind {
    /// Deriving the shared secret did not succeed.
    DeriveSharedSecretFailed,
    /// Key generation did not succeed.
    KeyGenerationFailed,
}

impl core::fmt::Display for KeyAgreementFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KeyAgreementFailureKind::DeriveSharedSecretFailed => "derive shared secret failed",
            KeyAgreementFailureKind::KeyGenerationFailed => "key generation failed",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a KEM (key encapsulation) operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemFailureKind {
    /// Key generation did not succeed.
    KeyGenerationFailed,
    /// Encapsulation did not succeed.
    EncapsulateFailed,
    /// Decapsulation did not succeed.
    DecapsulateFailed,
}

impl core::fmt::Display for KemFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KemFailureKind::KeyGenerationFailed => "key generation failed",
            KemFailureKind::EncapsulateFailed => "encapsulate failed",
            KemFailureKind::DecapsulateFailed => "decapsulate failed",
        };
        write!(f, "{detail}")
    }
}

/// Key-wrapping algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// AES-256 Key Wrap as specified by RFC 3394 / NIST SP 800-38F.
    Aes256Kw,
}

impl core::fmt::Display for KeyWrapAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KeyWrapAlgorithm::Aes256Kw => "AES-256-KW",
        };
        write!(f, "{detail}")
    }
}

/// Key-wrap operation being attempted when a failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapOperation {
    /// Wrapping plaintext key material.
    Wrap,
    /// Unwrapping wrapped key material.
    Unwrap,
}

impl core::fmt::Display for KeyWrapOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let op = match self {
            KeyWrapOperation::Wrap => "wrap",
            KeyWrapOperation::Unwrap => "unwrap",
        };
        write!(f, "{op}")
    }
}

/// Specific reason a key-wrap operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapFailureKind {
    /// The key-encryption key did not have the required length.
    InvalidKekLength,
    /// Plaintext key material was too short for RFC 3394 AES-KW.
    InvalidPlaintextLength,
    /// Wrapped key material was too short or malformed for RFC 3394 AES-KW.
    InvalidWrappedLength,
    /// An input or output length exceeded the representable range.
    LengthOverflow,
    /// The wrapped key integrity check failed.
    IntegrityCheckFailed,
    /// The backend reported an unspecified internal failure.
    BackendFailure,
}

impl core::fmt::Display for KeyWrapFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KeyWrapFailureKind::InvalidKekLength => "invalid key-encryption key length",
            KeyWrapFailureKind::InvalidPlaintextLength => "invalid plaintext key length",
            KeyWrapFailureKind::InvalidWrappedLength => "invalid wrapped key length",
            KeyWrapFailureKind::LengthOverflow => "length overflow",
            KeyWrapFailureKind::IntegrityCheckFailed => "integrity check failed",
            KeyWrapFailureKind::BackendFailure => "backend failure",
        };
        write!(f, "{detail}")
    }
}

/// Password-based key derivation algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// Argon2id memory-hard KDF.
    Argon2id,
    /// PBKDF2 password-based KDF for legacy interop.
    Pbkdf2,
}

impl core::fmt::Display for KdfAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KdfAlgorithm::Argon2id => "Argon2id",
            KdfAlgorithm::Pbkdf2 => "PBKDF2",
        };
        write!(f, "{detail}")
    }
}

/// Versioned parameter profile for the KDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfProfile {
    /// Argon2id parameter profile version 1.
    Argon2idV1,
    /// Argon2id parameter profile version 2.
    Argon2idV2,
    /// PBKDF2 using HMAC-SHA-256 as the PRF.
    Pbkdf2HmacSha256,
    /// PBKDF2 using HMAC-SHA-512 as the PRF.
    Pbkdf2HmacSha512,
}

impl core::fmt::Display for KdfProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KdfProfile::Argon2idV1 => "Argon2id v1",
            KdfProfile::Argon2idV2 => "Argon2id v2",
            KdfProfile::Pbkdf2HmacSha256 => "PBKDF2-HMAC-SHA-256",
            KdfProfile::Pbkdf2HmacSha512 => "PBKDF2-HMAC-SHA-512",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a KDF operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfFailureKind {
    /// The secret/password input had an unacceptable length.
    InvalidSecretLength,
    /// The salt input had an unacceptable length.
    InvalidSaltLength,
    /// The requested output length was unacceptable.
    InvalidOutputLength,
    /// The iteration count was zero or outside this API's accepted range.
    InvalidIterationCount,
    /// The supplied KDF parameters were invalid.
    InvalidParams,
    /// The derivation itself did not succeed.
    DerivationFailed,
}

impl core::fmt::Display for KdfFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KdfFailureKind::InvalidSecretLength => "invalid secret length",
            KdfFailureKind::InvalidSaltLength => "invalid salt length",
            KdfFailureKind::InvalidOutputLength => "invalid output length",
            KdfFailureKind::InvalidIterationCount => "invalid iteration count",
            KdfFailureKind::InvalidParams => "invalid parameters",
            KdfFailureKind::DerivationFailed => "derivation failed",
        };
        write!(f, "{detail}")
    }
}

/// Hash function underlying an HKDF operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfHash {
    /// HKDF using SHA-2-256.
    Sha2_256,
    /// HKDF using SHA-3-256.
    Sha3_256,
}

impl core::fmt::Display for HkdfHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            HkdfHash::Sha2_256 => "SHA2-256",
            HkdfHash::Sha3_256 => "SHA3-256",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason an HKDF operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfFailureKind {
    /// The input key material had an unacceptable length.
    InvalidIkmLength,
    /// The domain-separation tag had an unacceptable length.
    InvalidDomainTagLength,
    /// The domain-separation tag contained an invalid byte.
    InvalidDomainTagByte,
    /// An input length exceeded the representable range.
    LengthOverflow,
    /// The requested output length was unacceptable.
    InvalidOutputLength,
    /// The HKDF expand step did not succeed.
    ExpandFailed,
}

impl core::fmt::Display for HkdfFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            HkdfFailureKind::InvalidIkmLength => "invalid input key material length",
            HkdfFailureKind::InvalidDomainTagLength => "invalid domain tag length",
            HkdfFailureKind::InvalidDomainTagByte => "invalid domain tag byte",
            HkdfFailureKind::LengthOverflow => "length overflow",
            HkdfFailureKind::InvalidOutputLength => "invalid output length",
            HkdfFailureKind::ExpandFailed => "expand failed",
        };
        write!(f, "{detail}")
    }
}

/// Hash function underlying an HMAC operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacHash {
    /// HMAC using SHA-256.
    Sha2_256,
    /// HMAC using SHA-512.
    Sha2_512,
}

impl core::fmt::Display for MacHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            MacHash::Sha2_256 => "SHA-256",
            MacHash::Sha2_512 => "SHA-512",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason an HMAC operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacFailureKind {
    /// The supplied key was empty or exceeded the accepted size limit.
    InvalidKeyLength,
    /// The supplied authentication tag length did not match the algorithm.
    InvalidTagLength,
    /// Tag verification failed.
    VerificationFailed,
    /// The backend reported an unspecified internal failure.
    BackendFailure,
}

impl core::fmt::Display for MacFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            MacFailureKind::InvalidKeyLength => "invalid key length",
            MacFailureKind::InvalidTagLength => "invalid tag length",
            MacFailureKind::VerificationFailed => "verification failed",
            MacFailureKind::BackendFailure => "backend failure",
        };
        write!(f, "{detail}")
    }
}

/// Purpose of the random output being generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngOutputKind {
    /// Generic random bytes with no fixed length.
    Generic,
    /// A 12-byte AEAD nonce.
    AeadNonce12,
    /// A 16-byte Argon2 salt.
    Argon2Salt16,
    /// A 32-byte Argon2 salt.
    Argon2Salt32,
}

impl core::fmt::Display for RngOutputKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            RngOutputKind::Generic => "random bytes",
            RngOutputKind::AeadNonce12 => "AEAD nonce",
            RngOutputKind::Argon2Salt16 => "Argon2 16-byte salt",
            RngOutputKind::Argon2Salt32 => "Argon2 32-byte salt",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason secure random generation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngFailureKind {
    /// The system entropy source was unavailable.
    EntropyUnavailable,
    /// The requested output length was unacceptable.
    InvalidOutputLength,
}

impl core::fmt::Display for RngFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            RngFailureKind::EntropyUnavailable => "entropy unavailable",
            RngFailureKind::InvalidOutputLength => "invalid output length",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a constant-time comparison did not match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstantTimeFailureKind {
    /// The two inputs had different lengths.
    LengthMismatch,
    /// The two inputs had equal length but unequal contents.
    NotEqual,
}

impl core::fmt::Display for ConstantTimeFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            ConstantTimeFailureKind::LengthMismatch => "length mismatch",
            ConstantTimeFailureKind::NotEqual => "not equal",
        };
        write!(f, "{detail}")
    }
}

/// Typed error taxonomy for all crypto operations in the workspace.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
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
