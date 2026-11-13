// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Hash function bound into an RSA signature verification suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHash {
    /// SHA-1 for historical X.509/eMRTD document verification only.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl RsaHash {
    /// Numeric suite identifier used by the C FFI.
    pub const fn ffi_id(self) -> u32 {
        match self {
            Self::Sha1 => crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA1_FFI_ID,
            Self::Sha256 => crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA256_FFI_ID,
            Self::Sha384 => crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA384_FFI_ID,
            Self::Sha512 => crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA512_FFI_ID,
        }
    }

    /// Parses a C FFI suite identifier.
    pub const fn from_ffi_id(value: u32) -> Option<Self> {
        match value {
            crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA1_FFI_ID => Some(Self::Sha1),
            crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA256_FFI_ID => Some(Self::Sha256),
            crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA384_FFI_ID => Some(Self::Sha384),
            crypto_core::contract_constants::rsa_ffi::RSA_HASH_SHA512_FFI_ID => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Public-key DER encoding supplied by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPublicKeyDerEncoding {
    /// PKCS#1 `RSAPublicKey` DER.
    Pkcs1,
    /// X.509 SubjectPublicKeyInfo DER.
    Spki,
}

impl RsaPublicKeyDerEncoding {
    /// Numeric encoding identifier used by the C FFI.
    pub const fn ffi_id(self) -> u32 {
        match self {
            Self::Pkcs1 => crypto_core::contract_constants::rsa_ffi::RSA_DER_PKCS1_FFI_ID,
            Self::Spki => crypto_core::contract_constants::rsa_ffi::RSA_DER_SPKI_FFI_ID,
        }
    }

    /// Parses a C FFI encoding identifier.
    pub const fn from_ffi_id(value: u32) -> Option<Self> {
        match value {
            crypto_core::contract_constants::rsa_ffi::RSA_DER_PKCS1_FFI_ID => Some(Self::Pkcs1),
            crypto_core::contract_constants::rsa_ffi::RSA_DER_SPKI_FFI_ID => Some(Self::Spki),
            _ => None,
        }
    }
}

/// Parameters for RSASSA-PSS verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPssParams {
    /// Hash applied to the message before PSS verification.
    pub message_hash: RsaHash,
    /// Hash used by MGF1 inside PSS.
    pub mgf1_hash: RsaHash,
    /// Expected salt length in bytes.
    pub salt_len: usize,
}
