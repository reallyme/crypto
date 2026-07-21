// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Compile-time dispatch for feature-selected HPKE components.

/// Dispatches a registered KEM only when its reviewed implementation is part
/// of the current build. The fallback keeps recognized but disabled KEM IDs
/// fail-closed without importing their backend types.
macro_rules! dispatch_kem {
    ($kem:expr, $callback:ident $(, $argument:expr)* $(,)?) => {{
        match $kem {
            #[cfg(feature = "kem-dh-p256")]
            $crate::identifiers::HpkeKemId::DhKemP256HkdfSha256 => {
                $callback::<hpke::kem::DhP256HkdfSha256>($($argument),*)
            }
            #[cfg(feature = "kem-dh-p384")]
            $crate::identifiers::HpkeKemId::DhKemP384HkdfSha384 => {
                $callback::<hpke::kem::DhP384HkdfSha384>($($argument),*)
            }
            #[cfg(feature = "kem-dh-p521")]
            $crate::identifiers::HpkeKemId::DhKemP521HkdfSha512 => {
                $callback::<hpke::kem::DhP521HkdfSha512>($($argument),*)
            }
            #[cfg(feature = "kem-secp256k1")]
            $crate::identifiers::HpkeKemId::DhKemSecp256k1HkdfSha256 => {
                $callback::<$crate::secp256k1::DhKemSecp256k1HkdfSha256>($($argument),*)
            }
            #[cfg(feature = "kem-x25519")]
            $crate::identifiers::HpkeKemId::DhKemX25519HkdfSha256 => {
                $callback::<hpke::kem::X25519HkdfSha256>($($argument),*)
            }
            #[cfg(feature = "kem-x448")]
            $crate::identifiers::HpkeKemId::DhKemX448HkdfSha512 => {
                $callback::<$crate::x448::DhKemX448HkdfSha512>($($argument),*)
            }
            #[cfg(feature = "kem-ml-kem-512")]
            $crate::identifiers::HpkeKemId::MlKem512 => {
                $callback::<$crate::mlkem512::MlKem512>($($argument),*)
            }
            #[cfg(feature = "kem-ml-kem-768")]
            $crate::identifiers::HpkeKemId::MlKem768 => {
                $callback::<hpke::kem::MlKem768>($($argument),*)
            }
            #[cfg(feature = "kem-ml-kem-1024")]
            $crate::identifiers::HpkeKemId::MlKem1024 => {
                $callback::<hpke::kem::MlKem1024>($($argument),*)
            }
            #[cfg(feature = "kem-ml-kem-768-p256")]
            $crate::identifiers::HpkeKemId::MlKem768P256 => {
                $callback::<hpke::kem::MlKem768P256>($($argument),*)
            }
            #[cfg(feature = "kem-ml-kem-1024-p384")]
            $crate::identifiers::HpkeKemId::MlKem1024P384 => {
                $callback::<$crate::mlkem1024p384::MlKem1024P384>($($argument),*)
            }
            #[cfg(feature = "kem-x-wing")]
            $crate::identifiers::HpkeKemId::XWing => {
                $callback::<hpke::kem::XWing>($($argument),*)
            }
            _ => Err($crate::error::HpkeError::UnsupportedKem),
        }
    }};
}

/// Dispatches one enabled HPKE key-schedule KDF.
macro_rules! dispatch_kdf {
    ($kdf:expr, $callback:ident, $kem:ty $(, $argument:expr)* $(,)?) => {{
        match $kdf {
            #[cfg(feature = "kdf-hkdf-sha256")]
            $crate::identifiers::HpkeKdfId::HkdfSha256 => {
                $callback::<$kem, hpke::kdf::HkdfSha256>($($argument),*)
            }
            #[cfg(feature = "kdf-hkdf-sha384")]
            $crate::identifiers::HpkeKdfId::HkdfSha384 => {
                $callback::<$kem, hpke::kdf::HkdfSha384>($($argument),*)
            }
            #[cfg(feature = "kdf-hkdf-sha512")]
            $crate::identifiers::HpkeKdfId::HkdfSha512 => {
                $callback::<$kem, hpke::kdf::HkdfSha512>($($argument),*)
            }
            #[cfg(feature = "kdf-shake256")]
            $crate::identifiers::HpkeKdfId::Shake256 => {
                $callback::<$kem, hpke::kdf::KdfShake256>($($argument),*)
            }
            _ => Err($crate::error::HpkeError::UnsupportedKdf),
        }
    }};
}

/// Dispatches one enabled encrypting AEAD.
macro_rules! dispatch_sealing_aead {
    ($aead:expr, $callback:ident, $kdf:ty, $kem:ty $(, $argument:expr)* $(,)?) => {{
        match $aead {
            #[cfg(feature = "aead-aes128-gcm")]
            $crate::identifiers::HpkeAeadId::Aes128Gcm => {
                $callback::<hpke::aead::AesGcm128, $kdf, $kem>($($argument),*)
            }
            #[cfg(feature = "aead-aes256-gcm")]
            $crate::identifiers::HpkeAeadId::Aes256Gcm => {
                $callback::<hpke::aead::AesGcm256, $kdf, $kem>($($argument),*)
            }
            #[cfg(feature = "aead-chacha20-poly1305")]
            $crate::identifiers::HpkeAeadId::ChaCha20Poly1305 => {
                $callback::<hpke::aead::ChaCha20Poly1305, $kdf, $kem>($($argument),*)
            }
            _ => Err($crate::error::HpkeError::UnsupportedAead),
        }
    }};
}

/// Dispatches one enabled AEAD for exporter setup, including export-only mode.
macro_rules! dispatch_export_aead {
    ($aead:expr, $callback:ident, $kdf:ty, $kem:ty $(, $argument:expr)* $(,)?) => {{
        match $aead {
            #[cfg(feature = "aead-aes128-gcm")]
            $crate::identifiers::HpkeAeadId::Aes128Gcm => {
                $callback::<hpke::aead::AesGcm128, $kdf, $kem>($($argument),*)
            }
            #[cfg(feature = "aead-aes256-gcm")]
            $crate::identifiers::HpkeAeadId::Aes256Gcm => {
                $callback::<hpke::aead::AesGcm256, $kdf, $kem>($($argument),*)
            }
            #[cfg(feature = "aead-chacha20-poly1305")]
            $crate::identifiers::HpkeAeadId::ChaCha20Poly1305 => {
                $callback::<hpke::aead::ChaCha20Poly1305, $kdf, $kem>($($argument),*)
            }
            #[cfg(feature = "aead-export-only")]
            $crate::identifiers::HpkeAeadId::ExportOnly => {
                $callback::<hpke::aead::ExportOnlyAead, $kdf, $kem>($($argument),*)
            }
            #[cfg(not(all(
                feature = "aead-aes128-gcm",
                feature = "aead-aes256-gcm",
                feature = "aead-chacha20-poly1305",
                feature = "aead-export-only"
            )))]
            _ => Err($crate::error::HpkeError::UnsupportedAead),
        }
    }};
}
