// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF input keying material, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HkdfInputKeyMaterial {
    bytes: Vec<u8>,
}

impl HkdfInputKeyMaterial {
    /// Build input keying material by copying the given bytes.
    pub fn from_slice(input: &[u8]) -> Self {
        Self {
            bytes: input.to_vec(),
        }
    }

    /// Borrow the input keying material bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Optional HKDF salt value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HkdfSalt {
    bytes: Vec<u8>,
}

impl HkdfSalt {
    /// Build an HKDF salt by copying the given bytes.
    pub fn from_slice(input: &[u8]) -> Self {
        Self {
            bytes: input.to_vec(),
        }
    }

    /// Borrow the salt bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// HKDF `info` context/application-binding value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HkdfInfo {
    bytes: Vec<u8>,
}

impl HkdfInfo {
    /// Build an HKDF `info` value by copying the given bytes.
    pub fn from_slice(input: &[u8]) -> Self {
        Self {
            bytes: input.to_vec(),
        }
    }

    /// Borrow the `info` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Fixed-length HKDF output keying material, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HkdfOutput<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> HkdfOutput<N> {
    /// Borrow the `N`-byte derived output.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consume the output and return its `N`-byte array.
    pub fn into_bytes(self) -> [u8; N] {
        self.bytes
    }

    pub(crate) fn from_array(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}
