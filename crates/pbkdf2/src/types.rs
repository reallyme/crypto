// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{
    PBKDF2_MAX_ITERATIONS, PBKDF2_MAX_PASSWORD_LENGTH, PBKDF2_MAX_SALT_LENGTH,
    PBKDF2_MIN_PASSWORD_LENGTH, PBKDF2_MIN_SALT_LENGTH, PBKDF2_MODERN_MIN_ITERATIONS,
    PBKDF2_STANDARD_MIN_ITERATIONS,
};
#[cfg(any(feature = "native", feature = "wasm"))]
use crate::constants::{PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MIN_OUTPUT_LENGTH};

/// PRF used by PBKDF2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbkdf2Prf {
    /// PBKDF2 with HMAC-SHA-256.
    HmacSha256,
    /// PBKDF2 with HMAC-SHA-512.
    HmacSha512,
}

impl Pbkdf2Prf {
    pub(crate) fn profile(self) -> KdfProfile {
        match self {
            Pbkdf2Prf::HmacSha256 => KdfProfile::Pbkdf2HmacSha256,
            Pbkdf2Prf::HmacSha512 => KdfProfile::Pbkdf2HmacSha512,
        }
    }
}

/// Password/secret input to PBKDF2.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pbkdf2Password {
    bytes: Zeroizing<Vec<u8>>,
}

impl Pbkdf2Password {
    /// Constructs a PBKDF2 password input from raw bytes.
    pub fn from_slice(input: &[u8], prf: Pbkdf2Prf) -> Result<Self, CryptoError> {
        if !(PBKDF2_MIN_PASSWORD_LENGTH..=PBKDF2_MAX_PASSWORD_LENGTH).contains(&input.len()) {
            return Err(kdf_error(prf, KdfFailureKind::InvalidSecretLength));
        }

        Ok(Self {
            bytes: Zeroizing::new(input.to_vec()),
        })
    }

    /// Borrows the password bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Salt input to PBKDF2.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pbkdf2Salt {
    bytes: Zeroizing<Vec<u8>>,
}

impl Pbkdf2Salt {
    /// Constructs a PBKDF2 salt from raw bytes.
    pub fn from_slice(input: &[u8], prf: Pbkdf2Prf) -> Result<Self, CryptoError> {
        if !(PBKDF2_MIN_SALT_LENGTH..=PBKDF2_MAX_SALT_LENGTH).contains(&input.len()) {
            return Err(kdf_error(prf, KdfFailureKind::InvalidSaltLength));
        }

        Ok(Self {
            bytes: Zeroizing::new(input.to_vec()),
        })
    }

    /// Borrows the salt bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// PBKDF2 iteration count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pbkdf2Iterations {
    value: u32,
}

impl Pbkdf2Iterations {
    /// Constructs an iteration count.
    pub fn from_u32(value: u32, prf: Pbkdf2Prf) -> Result<Self, CryptoError> {
        if !(PBKDF2_STANDARD_MIN_ITERATIONS..=PBKDF2_MAX_ITERATIONS).contains(&value) {
            return Err(kdf_error(prf, KdfFailureKind::InvalidIterationCount));
        }
        Ok(Self { value })
    }

    /// Constructs an iteration count for a new public protocol profile.
    ///
    /// The standards-level constructor remains available for conformance
    /// vectors. Public facades use this constructor so a below-policy work
    /// factor cannot be selected accidentally.
    pub fn from_u32_modern(value: u32, prf: Pbkdf2Prf) -> Result<Self, CryptoError> {
        if !(PBKDF2_MODERN_MIN_ITERATIONS..=PBKDF2_MAX_ITERATIONS).contains(&value) {
            return Err(kdf_error(prf, KdfFailureKind::InvalidIterationCount));
        }
        Ok(Self { value })
    }

    /// Returns the raw iteration count.
    pub fn as_u32(self) -> u32 {
        self.value
    }
}

/// Derived PBKDF2 output keying material.
pub struct Pbkdf2Output {
    bytes: Zeroizing<Vec<u8>>,
}

impl Zeroize for Pbkdf2Output {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

// The inner owner already wipes the allocation on drop. Keeping this wrapper
// free of its own `Drop` implementation permits a no-copy ownership transfer.
impl ZeroizeOnDrop for Pbkdf2Output {}

impl Pbkdf2Output {
    #[cfg(any(feature = "native", feature = "wasm"))]
    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes }
    }

    /// Borrows the derived bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the derived byte length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this output is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the output and returns an owned zeroizing buffer.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl core::fmt::Debug for Pbkdf2Output {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Pbkdf2Output(len={})", self.len())
    }
}

#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) fn validate_output_len(len: usize, prf: Pbkdf2Prf) -> Result<(), CryptoError> {
    if !(PBKDF2_MIN_OUTPUT_LENGTH..=PBKDF2_MAX_OUTPUT_LENGTH).contains(&len) {
        return Err(kdf_error(prf, KdfFailureKind::InvalidOutputLength));
    }
    Ok(())
}

pub(crate) fn kdf_error(prf: Pbkdf2Prf, kind: KdfFailureKind) -> CryptoError {
    CryptoError::Kdf {
        algorithm: KdfAlgorithm::Pbkdf2,
        profile: prf.profile(),
        kind,
    }
}
