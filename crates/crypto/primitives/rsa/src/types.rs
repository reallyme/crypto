// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Hash function bound into an RSA signature verification suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHash {
    /// SHA-1 for legacy X.509/eMRTD verification only.
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
            Self::Sha1 => 1,
            Self::Sha256 => 2,
            Self::Sha384 => 3,
            Self::Sha512 => 4,
        }
    }

    /// Parses a C FFI suite identifier.
    pub const fn from_ffi_id(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            3 => Some(Self::Sha384),
            4 => Some(Self::Sha512),
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
            Self::Pkcs1 => 1,
            Self::Spki => 2,
        }
    }

    /// Parses a C FFI encoding identifier.
    pub const fn from_ffi_id(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Pkcs1),
            2 => Some(Self::Spki),
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
