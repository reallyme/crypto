// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Authenticated plaintext with automatic clearing and no diagnostic exposure.
/// Borrowed bytes remain valid only while this owner is alive. Copies made by
/// the caller need their own clearing owner.
///
/// ```compile_fail
/// use crypto_hpke::base_p256::P256BasePlaintext;
/// fn diagnostic<T: core::fmt::Debug>() {}
/// diagnostic::<P256BasePlaintext>();
/// ```
pub struct P256BasePlaintext {
    bytes: Zeroizing<Vec<u8>>,
}

impl P256BasePlaintext {
    pub(super) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes }
    }

    /// Borrow the authenticated plaintext without transferring ownership.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Number of authenticated plaintext bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the authenticated record has no plaintext bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Zeroize for P256BasePlaintext {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for P256BasePlaintext {}
