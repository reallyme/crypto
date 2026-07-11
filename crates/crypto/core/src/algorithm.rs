// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Asymmetric algorithm identifiers used for signatures and key agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Ed25519 EdDSA signature algorithm.
    Ed25519,
    /// X25519 Diffie-Hellman key agreement.
    X25519,
    /// NIST P-256 (secp256r1) ECDSA signature and ECDH key agreement.
    P256,
    /// NIST P-384 (secp384r1) ECDSA signature algorithm.
    P384,
    /// NIST P-521 (secp521r1) ECDSA signature algorithm.
    P521,
    /// secp256k1 ECDSA signature algorithm.
    Secp256k1,
    /// ML-DSA-44 post-quantum signature algorithm.
    MlDsa44,
    /// ML-DSA-65 post-quantum signature algorithm.
    MlDsa65,
    /// ML-DSA-87 post-quantum signature algorithm.
    MlDsa87,
    /// ML-KEM-512 post-quantum key encapsulation.
    MlKem512,
    /// ML-KEM-768 post-quantum key encapsulation.
    MlKem768,
    /// ML-KEM-1024 post-quantum key encapsulation.
    MlKem1024,
    /// X-Wing hybrid KEM over X25519 and ML-KEM-768.
    XWing768,
    /// X-Wing hybrid KEM over X25519 and ML-KEM-1024.
    XWing1024,
}

impl Algorithm {
    /// Canonical protocol identifier string.
    /// MUST match multicodec `alg` strings exactly.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::X25519 => "X25519",
            Algorithm::P256 => "P-256",
            Algorithm::P384 => "P-384",
            Algorithm::P521 => "P-521",
            Algorithm::Secp256k1 => "secp256k1",
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::MlKem512 => "ML-KEM-512",
            Algorithm::MlKem768 => "ML-KEM-768",
            Algorithm::MlKem1024 => "ML-KEM-1024",
            Algorithm::XWing768 => "X-Wing-768",
            Algorithm::XWing1024 => "X-Wing-1024",
        }
    }

    /// True if this algorithm produces digital signatures
    pub fn is_signature(self) -> bool {
        matches!(
            self,
            Algorithm::Ed25519
                | Algorithm::P256
                | Algorithm::P384
                | Algorithm::P521
                | Algorithm::Secp256k1
                | Algorithm::MlDsa44
                | Algorithm::MlDsa65
                | Algorithm::MlDsa87
        )
    }

    /// True if this algorithm is for key agreement / encapsulation
    pub fn is_key_agreement(self) -> bool {
        matches!(
            self,
            Algorithm::X25519
                | Algorithm::P256
                | Algorithm::MlKem512
                | Algorithm::MlKem768
                | Algorithm::MlKem1024
                | Algorithm::XWing768
                | Algorithm::XWing1024
        )
    }
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Authenticated encryption (AEAD) algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    /// AES-256 in Galois/Counter Mode.
    Aes256Gcm,
    /// AES-256 in GCM-SIV (nonce-misuse-resistant) mode.
    Aes256GcmSiv,
    /// ChaCha20-Poly1305 with a 96-bit RFC 8439 nonce.
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 with a 192-bit extended nonce.
    XChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Canonical protocol identifier string.
    pub fn as_str(self) -> &'static str {
        match self {
            AeadAlgorithm::Aes256Gcm => "AES-256-GCM",
            AeadAlgorithm::Aes256GcmSiv => "AES-256-GCM-SIV",
            AeadAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            AeadAlgorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }
}

impl core::fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Hash algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-2 with a 256-bit digest.
    Sha2_256,
    /// SHA-2 with a 384-bit digest.
    Sha2_384,
    /// SHA-2 with a 512-bit digest.
    Sha2_512,
    /// SHA-3 with a 224-bit digest.
    Sha3_224,
    /// SHA-3 with a 256-bit digest.
    Sha3_256,
    /// SHA-3 with a 384-bit digest.
    Sha3_384,
    /// SHA-3 with a 512-bit digest.
    Sha3_512,
}

impl HashAlgorithm {
    /// Canonical protocol identifier string.
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlgorithm::Sha2_256 => "SHA2-256",
            HashAlgorithm::Sha2_384 => "SHA2-384",
            HashAlgorithm::Sha2_512 => "SHA2-512",
            HashAlgorithm::Sha3_224 => "SHA3-224",
            HashAlgorithm::Sha3_256 => "SHA3-256",
            HashAlgorithm::Sha3_384 => "SHA3-384",
            HashAlgorithm::Sha3_512 => "SHA3-512",
        }
    }
}

impl core::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Message authentication code algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacAlgorithm {
    /// HMAC using SHA-256.
    HmacSha256,
    /// HMAC using SHA-512.
    HmacSha512,
}

impl MacAlgorithm {
    /// Canonical protocol identifier string.
    pub fn as_str(self) -> &'static str {
        match self {
            MacAlgorithm::HmacSha256 => "HMAC-SHA-256",
            MacAlgorithm::HmacSha512 => "HMAC-SHA-512",
        }
    }
}

impl core::fmt::Display for MacAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
