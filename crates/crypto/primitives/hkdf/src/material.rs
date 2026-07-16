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

/// Optional HKDF salt value, zeroized on drop.
///
/// HKDF salts can carry protocol or user correlation material. The wrapper
/// deliberately has no `Debug` or `Clone` implementation so accidental logs
/// and unmanaged duplicate buffers are not part of the public API.
#[derive(Zeroize, ZeroizeOnDrop)]
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
    ///
    /// The returned array is no longer zeroized by this type. Callers must wipe
    /// it as soon as the derived key material is no longer needed.
    pub fn into_bytes(mut self) -> [u8; N] {
        let output = self.bytes;
        self.bytes.zeroize();
        output
    }

    pub(crate) fn from_array(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}
