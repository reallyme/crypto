// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length in bytes of an HKDF-SHA384 pseudorandom key.
pub const HKDF_SHA384_PRK_LENGTH: usize = 48;

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
///
/// Context can contain stable protocol or user bindings. The owner clears its
/// allocation on drop and redacts `Debug` output so those bindings are not
/// retained in allocator memory or copied into logs.
#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct HkdfInfo {
    bytes: Vec<u8>,
}

impl core::fmt::Debug for HkdfInfo {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HkdfInfo(<redacted>)")
    }
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

/// Pseudorandom key produced by HKDF-SHA384 extract.
///
/// The PRK is secret key material. It has no `Debug`, `Display`, `Clone`, or
/// serialization implementation and is zeroized when its owner is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HkdfSha384Prk {
    bytes: [u8; HKDF_SHA384_PRK_LENGTH],
}

impl HkdfSha384Prk {
    /// Borrows the fixed-size PRK for use by HKDF expand.
    pub fn as_bytes(&self) -> &[u8; HKDF_SHA384_PRK_LENGTH] {
        &self.bytes
    }

    pub(crate) fn from_array(bytes: [u8; HKDF_SHA384_PRK_LENGTH]) -> Self {
        Self { bytes }
    }
}

impl<const N: usize> HkdfOutput<N> {
    /// Borrow the `N`-byte derived output.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the output and returns an owned zeroizing array.
    pub fn into_zeroizing(self) -> Zeroizing<[u8; N]> {
        Zeroizing::new(self.bytes)
    }

    pub(crate) fn from_array(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}
