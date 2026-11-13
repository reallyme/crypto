// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Password-based key derivation algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfAlgorithm {
    /// Argon2id memory-hard KDF.
    Argon2id,
    /// PBKDF2 password-based KDF conforming to RFC 8018.
    Pbkdf2,
    /// NIST Concat KDF as profiled by JOSE/JWA ECDH-ES.
    ConcatKdf,
    /// KMAC256 from NIST SP 800-185.
    Kmac256,
}

impl core::fmt::Display for KdfAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KdfAlgorithm::Argon2id => "Argon2id",
            KdfAlgorithm::Pbkdf2 => "PBKDF2",
            KdfAlgorithm::ConcatKdf => "Concat KDF",
            KdfAlgorithm::Kmac256 => "KMAC256",
        };
        write!(f, "{detail}")
    }
}

/// Versioned parameter profile for the KDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfProfile {
    /// Argon2id parameter profile version 1.
    Argon2idV1,
    /// Argon2id parameter profile version 2.
    Argon2idV2,
    /// PBKDF2 using HMAC-SHA-256 as the PRF.
    Pbkdf2HmacSha256,
    /// PBKDF2 using HMAC-SHA-512 as the PRF.
    Pbkdf2HmacSha512,
    /// JWA ECDH-ES Concat KDF using SHA-256.
    JwaEcdhEsSha256,
    /// NIST SP 800-185 KMAC256 with caller-supplied input and customization.
    Sp800185Kmac256,
}

impl core::fmt::Display for KdfProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KdfProfile::Argon2idV1 => "Argon2id v1",
            KdfProfile::Argon2idV2 => "Argon2id v2",
            KdfProfile::Pbkdf2HmacSha256 => "PBKDF2-HMAC-SHA-256",
            KdfProfile::Pbkdf2HmacSha512 => "PBKDF2-HMAC-SHA-512",
            KdfProfile::JwaEcdhEsSha256 => "JWA ECDH-ES Concat KDF SHA-256",
            KdfProfile::Sp800185Kmac256 => "SP 800-185 KMAC256",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a KDF operation failed.
pub type KdfFailureKind = super::CryptoError;

/// Hash function underlying an HKDF operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HkdfHash {
    /// HKDF using SHA-2-256.
    Sha2_256,
    /// HKDF using SHA-2-384.
    Sha2_384,
    /// HKDF using SHA-3-256.
    Sha3_256,
}

impl core::fmt::Display for HkdfHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            HkdfHash::Sha2_256 => "SHA2-256",
            HkdfHash::Sha2_384 => "SHA2-384",
            HkdfHash::Sha3_256 => "SHA3-256",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason an HKDF operation failed.
pub type HkdfFailureKind = super::CryptoError;
