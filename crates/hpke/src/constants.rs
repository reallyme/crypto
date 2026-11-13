// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// HPKE KEM identifier for DHKEM(P-256, HKDF-SHA256).
pub const HPKE_KEM_DHKEM_P256_HKDF_SHA256: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_P256_HKDF_SHA256;
/// HPKE KEM identifier for DHKEM(P-384, HKDF-SHA384).
pub const HPKE_KEM_DHKEM_P384_HKDF_SHA384: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_P384_HKDF_SHA384;
/// HPKE KEM identifier for DHKEM(P-521, HKDF-SHA512).
pub const HPKE_KEM_DHKEM_P521_HKDF_SHA512: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_P521_HKDF_SHA512;
/// HPKE KEM identifier for DHKEM(CP-256, HKDF-SHA256).
pub const HPKE_KEM_DHKEM_CP256_HKDF_SHA256: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_CP256_HKDF_SHA256;
/// HPKE KEM identifier for DHKEM(CP-384, HKDF-SHA384).
pub const HPKE_KEM_DHKEM_CP384_HKDF_SHA384: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_CP384_HKDF_SHA384;
/// HPKE KEM identifier for DHKEM(CP-521, HKDF-SHA512).
pub const HPKE_KEM_DHKEM_CP521_HKDF_SHA512: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_CP521_HKDF_SHA512;
/// HPKE KEM identifier for DHKEM(secp256k1, HKDF-SHA256).
pub const HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256;
/// HPKE KEM identifier for DHKEM(X25519, HKDF-SHA256).
pub const HPKE_KEM_DHKEM_X25519_HKDF_SHA256: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_X25519_HKDF_SHA256;
/// HPKE KEM identifier for DHKEM(X448, HKDF-SHA512).
pub const HPKE_KEM_DHKEM_X448_HKDF_SHA512: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_X448_HKDF_SHA512;
/// HPKE KEM identifier for DHKEM(X25519+Elligator, HKDF-SHA256).
pub const HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256;
/// HPKE KEM identifier for the historical X25519Kyber768Draft00 construction.
pub const HPKE_KEM_X25519_KYBER768_DRAFT00: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_X25519_KYBER768_DRAFT00;
/// HPKE KEM identifier for ML-KEM-512.
pub const HPKE_KEM_ML_KEM_512: u16 = crypto_core::contract_constants::hpke::HPKE_KEM_ML_KEM_512;
/// HPKE KEM identifier for ML-KEM-768.
pub const HPKE_KEM_ML_KEM_768: u16 = crypto_core::contract_constants::hpke::HPKE_KEM_ML_KEM_768;
/// HPKE KEM identifier for ML-KEM-1024.
pub const HPKE_KEM_ML_KEM_1024: u16 = crypto_core::contract_constants::hpke::HPKE_KEM_ML_KEM_1024;
/// HPKE KEM identifier for MLKEM768-P256.
pub const HPKE_KEM_ML_KEM_768_P256: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_ML_KEM_768_P256;
/// HPKE KEM identifier for MLKEM1024-P384.
pub const HPKE_KEM_ML_KEM_1024_P384: u16 =
    crypto_core::contract_constants::hpke::HPKE_KEM_ML_KEM_1024_P384;
/// HPKE KEM identifier for X-Wing.
pub const HPKE_KEM_X_WING: u16 = crypto_core::contract_constants::hpke::HPKE_KEM_X_WING;

/// HPKE KDF identifier for HKDF-SHA256.
pub const HPKE_KDF_HKDF_SHA256: u16 = crypto_core::contract_constants::hpke::HPKE_KDF_HKDF_SHA256;
/// HPKE KDF identifier for HKDF-SHA384.
pub const HPKE_KDF_HKDF_SHA384: u16 = crypto_core::contract_constants::hpke::HPKE_KDF_HKDF_SHA384;
/// HPKE KDF identifier for HKDF-SHA512.
pub const HPKE_KDF_HKDF_SHA512: u16 = crypto_core::contract_constants::hpke::HPKE_KDF_HKDF_SHA512;
/// HPKE KDF identifier for SHAKE128.
pub const HPKE_KDF_SHAKE128: u16 = crypto_core::contract_constants::hpke::HPKE_KDF_SHAKE128;
/// HPKE KDF identifier for SHAKE256.
pub const HPKE_KDF_SHAKE256: u16 = crypto_core::contract_constants::hpke::HPKE_KDF_SHAKE256;
/// HPKE KDF identifier for TurboSHAKE128.
pub const HPKE_KDF_TURBO_SHAKE128: u16 =
    crypto_core::contract_constants::hpke::HPKE_KDF_TURBO_SHAKE128;
/// HPKE KDF identifier for TurboSHAKE256.
pub const HPKE_KDF_TURBO_SHAKE256: u16 =
    crypto_core::contract_constants::hpke::HPKE_KDF_TURBO_SHAKE256;

/// HPKE AEAD identifier for AES-128-GCM.
pub const HPKE_AEAD_AES_128_GCM: u16 = crypto_core::contract_constants::hpke::HPKE_AEAD_AES_128_GCM;
/// HPKE AEAD identifier for AES-256-GCM.
pub const HPKE_AEAD_AES_256_GCM: u16 = crypto_core::contract_constants::hpke::HPKE_AEAD_AES_256_GCM;
/// HPKE AEAD identifier for ChaCha20-Poly1305.
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 =
    crypto_core::contract_constants::hpke::HPKE_AEAD_CHACHA20_POLY1305;
/// HPKE export-only AEAD identifier.
pub const HPKE_AEAD_EXPORT_ONLY: u16 = crypto_core::contract_constants::hpke::HPKE_AEAD_EXPORT_ONLY;

/// AES-GCM and ChaCha20-Poly1305 authentication tag length in HPKE.
pub const HPKE_AEAD_TAG_LEN: usize = crypto_core::contract_constants::hpke::HPKE_AEAD_TAG_LEN;
/// Nonce length derived by each supported HPKE encrypting AEAD.
pub const HPKE_AEAD_NONCE_LEN: usize = crypto_core::contract_constants::hpke::HPKE_AEAD_NONCE_LEN;
/// Minimum entropy-bearing PSK byte length required by RFC 9180.
pub const HPKE_MIN_PSK_LEN: usize = crypto_core::contract_constants::hpke::HPKE_MIN_PSK_LEN;
/// Maximum combined `info`, PSK identifier, and fixed-label length.
#[cfg(feature = "backend-native")]
pub const HPKE_LABELED_CONTEXT_LIMIT: usize =
    crypto_core::contract_constants::hpke::HPKE_LABELED_CONTEXT_LIMIT;
/// Fixed label bytes included in the key-schedule context length check.
#[cfg(feature = "backend-native")]
pub const HPKE_KEY_SCHEDULE_LABEL_OVERHEAD: usize =
    crypto_core::contract_constants::hpke::HPKE_KEY_SCHEDULE_LABEL_OVERHEAD;
/// Maximum registered encapsulated-key length exposed by this package.
pub const HPKE_ENCAPSULATED_KEY_MAX_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_ENCAPSULATED_KEY_MAX_LEN;
/// Maximum public-key length exposed by this package.
pub const HPKE_PUBLIC_KEY_MAX_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_PUBLIC_KEY_MAX_LEN;
/// Maximum private-key or deterministic IKM length exposed by this package.
pub const HPKE_PRIVATE_KEY_MAX_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_PRIVATE_KEY_MAX_LEN;

/// SEC1 uncompressed P-256 HPKE public key length.
pub const HPKE_P256_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_P256_PUBLIC_KEY_LEN;
/// P-256 scalar private key length.
pub const HPKE_P256_PRIVATE_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_P256_PRIVATE_KEY_LEN;
/// SEC1 uncompressed P-384 HPKE public key length.
pub const HPKE_P384_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_P384_PUBLIC_KEY_LEN;
/// P-384 scalar private key length.
pub const HPKE_P384_PRIVATE_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_P384_PRIVATE_KEY_LEN;
/// SEC1 uncompressed P-521 HPKE public key length.
pub const HPKE_P521_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_P521_PUBLIC_KEY_LEN;
/// P-521 scalar private key length.
pub const HPKE_P521_PRIVATE_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_P521_PRIVATE_KEY_LEN;
/// SEC1 uncompressed secp256k1 HPKE public key length.
pub const HPKE_SECP256K1_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_SECP256K1_PUBLIC_KEY_LEN;
/// secp256k1 scalar private key length.
pub const HPKE_SECP256K1_PRIVATE_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_SECP256K1_PRIVATE_KEY_LEN;
/// X25519 HPKE public key length.
pub const HPKE_X25519_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_X25519_PUBLIC_KEY_LEN;
/// X25519 HPKE private key length.
pub const HPKE_X25519_PRIVATE_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_X25519_PRIVATE_KEY_LEN;
/// X448 HPKE public key length.
pub const HPKE_X448_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_X448_PUBLIC_KEY_LEN;
/// X448 HPKE private key length.
pub const HPKE_X448_PRIVATE_KEY_LEN: usize =
    crypto_core::contract_constants::hpke::HPKE_X448_PRIVATE_KEY_LEN;

// RFC 9180 KEM context bytes bind the canonical two-byte registry identity.
// Destructuring the fixed-width representation avoids narrowing casts and
// keeps protocol byte order independent of the host architecture.
#[cfg(any(
    feature = "kem-ml-kem-512",
    feature = "kem-ml-kem-1024-p384",
    feature = "kem-secp256k1",
    feature = "kem-x448"
))]
pub(crate) const fn encode_kem_suite_id(kem_id: u16) -> [u8; 5] {
    let [high, low] = kem_id.to_be_bytes();
    [b'K', b'E', b'M', high, low]
}

#[cfg(any(
    feature = "kem-ml-kem-512",
    feature = "kem-ml-kem-1024-p384",
    feature = "kem-secp256k1",
    feature = "kem-x448"
))]
#[cfg(test)]
#[path = "constants_tests.rs"]
mod tests;
