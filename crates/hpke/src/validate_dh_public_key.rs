// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::identifiers::HpkeKemId;

/// Reject non-contributory DH inputs before backend setup can erase the
/// distinction between a bad peer key and an internal encapsulation failure.
pub(crate) fn has_contributory_dh_public_key(kem: HpkeKemId, encoded: &[u8]) -> bool {
    match kem {
        #[cfg(feature = "kem-x25519")]
        HpkeKemId::DhKemX25519HkdfSha256 => {
            let Ok(bytes) = <&[u8; crate::HPKE_X25519_PUBLIC_KEY_LEN]>::try_from(encoded) else {
                return false;
            };
            let point = curve25519_dalek::montgomery::MontgomeryPoint(*bytes);
            // Reuse the backend's complete low-order table. MontgomeryPoint
            // equality reduces modulo p and ignores the RFC 7748 high bit,
            // so alternate encodings cannot bypass this admission check.
            !curve25519_dalek::constants::X25519_LOW_ORDER_POINTS.contains(&point)
        }
        #[cfg(feature = "kem-x448")]
        HpkeKemId::DhKemX448HkdfSha512 => crypto_x448::X448PublicKey::from_bytes(encoded).is_ok(),
        _ => true,
    }
}
