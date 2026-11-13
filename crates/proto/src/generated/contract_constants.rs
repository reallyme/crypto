// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from immutable schema metadata. Regenerate with scripts/generate_error_contract.mjs.

/// Immutable `adapter_limits` contract constants.
pub mod adapter_limits {
    /// Exact count value declared by the schema.
    pub const MAX_FFI_INPUT_RANGES_PER_CALL: usize = 32;
    /// Exact count value declared by the schema.
    pub const MAX_FFI_OUTPUT_RANGES_PER_CALL: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const MAX_JNI_BYTE_INPUT_LENGTH: usize = 1048576;
    /// Exact bytes value declared by the schema.
    pub const MAX_WASM_CIPHERTEXT_LENGTH: usize = 1048592;
    /// Exact bytes value declared by the schema.
    pub const MAX_WASM_INPUT_LENGTH: usize = 1048576;
}

/// Immutable `aes256_gcm` contract constants.
pub mod aes256_gcm {
    /// Exact bytes value declared by the schema.
    pub const AES_128_GCM_KEY_LENGTH: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const AES_192_GCM_KEY_LENGTH: usize = 24;
    /// Exact bytes value declared by the schema.
    pub const AES_256_GCM_KEY_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const AES_256_GCM_NONCE_LENGTH: usize = 12;
    /// Exact bytes value declared by the schema.
    pub const AES_256_GCM_TAG_LENGTH: usize = 16;
}

/// Immutable `aes256_gcm_siv` contract constants.
pub mod aes256_gcm_siv {
    /// Exact bytes value declared by the schema.
    pub const AES_256_GCM_SIV_KEY_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const AES_256_GCM_SIV_NONCE_LENGTH: usize = 12;
    /// Exact bytes value declared by the schema.
    pub const AES_256_GCM_SIV_TAG_LENGTH: usize = 16;
}

/// Immutable `aes_kw` contract constants.
pub mod aes_kw {
    /// Exact bytes value declared by the schema.
    pub const AES_128_KW_KEK_LENGTH: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const AES_192_KW_KEK_LENGTH: usize = 24;
    /// Exact bytes value declared by the schema.
    pub const AES_256_KW_KEK_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const AES_KW_BLOCK_LENGTH: usize = 8;
    /// Exact bytes value declared by the schema.
    pub const AES_KW_INTEGRITY_CHECK_LENGTH: usize = 8;
    /// Exact bytes value declared by the schema.
    pub const AES_KW_MAX_KEY_DATA_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const AES_KW_MAX_WRAPPED_KEY_LENGTH: usize = 4104;
    /// Exact bytes value declared by the schema.
    pub const AES_KW_MIN_KEY_DATA_LENGTH: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const AES_KW_MIN_WRAPPED_KEY_LENGTH: usize = 24;
}

/// Immutable `argon2id` contract constants.
pub mod argon2id {
    /// Exact identifier value declared by the schema.
    pub const ARGON2ID_ALGORITHM_VERSION: u32 = 19;
    /// Exact bytes value declared by the schema.
    pub const ARGON2ID_DERIVED_KEY_LENGTH: usize = 32;
    /// Exact lanes value declared by the schema.
    pub const ARGON2ID_DESKTOP_MODERN_LANES_CAP: u32 = 4;
    /// Exact kibibytes value declared by the schema.
    pub const ARGON2ID_DESKTOP_MODERN_MEMORY_CAP_KIB: u32 = 2097152;
    /// Exact passes value declared by the schema.
    pub const ARGON2ID_DESKTOP_MODERN_TIME_COST_CAP: u32 = 6;
    /// Exact lanes value declared by the schema.
    pub const ARGON2ID_MOBILE_MODERN_LANES_CAP: u32 = 4;
    /// Exact kibibytes value declared by the schema.
    pub const ARGON2ID_MOBILE_MODERN_MEMORY_CAP_KIB: u32 = 524288;
    /// Exact passes value declared by the schema.
    pub const ARGON2ID_MOBILE_MODERN_TIME_COST_CAP: u32 = 4;
    /// Exact bytes value declared by the schema.
    pub const ARGON2ID_SALT_MAX_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ARGON2ID_SALT_MIN_LENGTH: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const ARGON2ID_SECRET_MAX_LENGTH: usize = 1048576;
    /// Exact bytes value declared by the schema.
    pub const ARGON2ID_SECRET_MIN_LENGTH: usize = 1;
    /// Exact lanes value declared by the schema.
    pub const ARGON2ID_V1_LANES: u32 = 1;
    /// Exact kibibytes value declared by the schema.
    pub const ARGON2ID_V1_MEMORY_COST_KIB: u32 = 262144;
    /// Exact passes value declared by the schema.
    pub const ARGON2ID_V1_TIME_COST: u32 = 3;
    /// Exact lanes value declared by the schema.
    pub const ARGON2ID_V2_LANES: u32 = 1;
    /// Exact kibibytes value declared by the schema.
    pub const ARGON2ID_V2_MEMORY_COST_KIB: u32 = 524288;
    /// Exact passes value declared by the schema.
    pub const ARGON2ID_V2_TIME_COST: u32 = 3;
}

/// Immutable `chacha20_poly1305` contract constants.
pub mod chacha20_poly1305 {
    /// Exact bytes value declared by the schema.
    pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const CHACHA20_POLY1305_NONCE_LENGTH: usize = 12;
    /// Exact bytes value declared by the schema.
    pub const CHACHA20_POLY1305_TAG_LENGTH: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const XCHACHA20_POLY1305_NONCE_LENGTH: usize = 24;
}

/// Immutable `concat_kdf` contract constants.
pub mod concat_kdf {
    /// Exact bytes value declared by the schema.
    pub const JWA_CONCAT_KDF_MAX_INFO_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const JWA_CONCAT_KDF_MIN_ALGORITHM_ID_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const JWA_CONCAT_KDF_MIN_OUTPUT_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const JWA_CONCAT_KDF_MIN_SHARED_SECRET_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH: usize = 32;
}

/// Immutable `csprng` contract constants.
pub mod csprng {
    /// Exact bytes value declared by the schema.
    pub const AEAD_NONCE_12_LENGTH: usize = 12;
    /// Exact bytes value declared by the schema.
    pub const AES_256_GCM_KEY_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ARGON2_SALT_16_LENGTH: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const ARGON2_SALT_32_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_87_SEED_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_1024_SEED_LENGTH: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const RANDOM_BYTES_MIN_LENGTH: usize = 1;
}

/// Immutable `ecdsa_explicit` contract constants.
pub mod ecdsa_explicit {
    /// Exact bytes value declared by the schema.
    pub const BRAINPOOL_P256_SCALAR_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const BRAINPOOL_P320_SCALAR_LEN: usize = 40;
    /// Exact bytes value declared by the schema.
    pub const BRAINPOOL_P384_SCALAR_LEN: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const BRAINPOOL_P512_SCALAR_LEN: usize = 64;
    /// Exact levels value declared by the schema.
    pub const DER_PAIR_DEPTH: usize = 1;
    /// Exact count value declared by the schema.
    pub const DER_PAIR_ELEMENTS: usize = 3;
    /// Exact count value declared by the schema.
    pub const GENERATION_ATTEMPTS: usize = 128;
    /// Exact bytes value declared by the schema.
    pub const MAX_DER_OVERHEAD: usize = 9;
}

/// Immutable `ed25519` contract constants.
pub mod ed25519 {
    /// Exact bytes value declared by the schema.
    pub const ED25519_POINT_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ED25519_SECRET_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ED25519_SEED_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ED25519_SIGNATURE_LENGTH: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const PUBLIC_KEY_LENGTH: usize = 32;
}

/// Immutable `ed448` contract constants.
pub mod ed448 {
    /// Exact bytes value declared by the schema.
    pub const PUBLIC_KEY_LEN: usize = 57;
    /// Exact bytes value declared by the schema.
    pub const SEED_LEN: usize = 57;
    /// Exact bytes value declared by the schema.
    pub const SIGNATURE_LEN: usize = 114;
}

/// Immutable `ffi_status` contract constants.
pub mod ffi_status {
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_AUTHENTICATION_FAILED: i32 = -6;
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_BUFFER_TOO_SMALL: i32 = -5;
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_INTERNAL_ERROR: i32 = -128;
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_INVALID_ARGUMENT: i32 = -1;
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_INVALID_CIPHERTEXT: i32 = -4;
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_INVALID_KEY: i32 = -2;
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_INVALID_SIGNATURE: i32 = -3;
    /// Exact identifier value declared by the schema.
    pub const CRYPTO_OK: i32 = 0;
}

/// Immutable `ffi_suite` contract constants.
pub mod ffi_suite {
    /// Exact identifier value declared by the schema.
    pub const HKDF_SUITE_SHA2_256: u32 = 1;
    /// Exact identifier value declared by the schema.
    pub const HKDF_SUITE_SHA3_256: u32 = 2;
    /// Exact identifier value declared by the schema.
    pub const HMAC_SUITE_SHA256: u32 = 1;
    /// Exact identifier value declared by the schema.
    pub const HMAC_SUITE_SHA512: u32 = 2;
    /// Exact identifier value declared by the schema.
    pub const HPKE_SUITE_P256_SHA256_AES256GCM: u32 = 1;
    /// Exact identifier value declared by the schema.
    pub const HPKE_SUITE_X25519_SHA256_CHACHA20_POLY1305: u32 = 2;
}

/// Immutable `hkdf` contract constants.
pub mod hkdf {
    /// Exact bytes value declared by the schema.
    pub const HKDF_DOMAIN_KEY_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const HKDF_DOMAIN_TAG_MAX_LENGTH: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const HKDF_DOMAIN_TAG_MIN_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const HKDF_MIN_OUTPUT_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const HKDF_SHA384_MAX_OUTPUT_LENGTH: usize = 12240;
    /// Exact bytes value declared by the schema.
    pub const HKDF_SHA384_PRK_LENGTH: usize = 48;
}

/// Immutable `hmac` contract constants.
pub mod hmac {
    /// Exact bytes value declared by the schema.
    pub const HMAC_MAX_KEY_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const HMAC_MIN_KEY_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const HMAC_SHA256_TAG_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const HMAC_SHA384_TAG_LENGTH: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const HMAC_SHA512_TAG_LENGTH: usize = 64;
}

/// Immutable `hpke` contract constants.
pub mod hpke {
    /// Exact identifier value declared by the schema.
    pub const HPKE_AEAD_AES_128_GCM: u16 = 1;
    /// Exact identifier value declared by the schema.
    pub const HPKE_AEAD_AES_256_GCM: u16 = 2;
    /// Exact identifier value declared by the schema.
    pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 3;
    /// Exact identifier value declared by the schema.
    pub const HPKE_AEAD_EXPORT_ONLY: u16 = 65535;
    /// Exact bytes value declared by the schema.
    pub const HPKE_AEAD_NONCE_LEN: usize = 12;
    /// Exact bytes value declared by the schema.
    pub const HPKE_AEAD_TAG_LEN: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const HPKE_ENCAPSULATED_KEY_MAX_LEN: usize = 1665;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KDF_HKDF_SHA256: u16 = 1;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KDF_HKDF_SHA384: u16 = 2;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KDF_HKDF_SHA512: u16 = 3;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KDF_SHAKE128: u16 = 16;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KDF_SHAKE256: u16 = 17;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KDF_TURBO_SHAKE128: u16 = 18;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KDF_TURBO_SHAKE256: u16 = 19;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_CP256_HKDF_SHA256: u16 = 19;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_CP384_HKDF_SHA384: u16 = 20;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_CP521_HKDF_SHA512: u16 = 21;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_P256_HKDF_SHA256: u16 = 16;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_P384_HKDF_SHA384: u16 = 17;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_P521_HKDF_SHA512: u16 = 18;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256: u16 = 22;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256: u16 = 34;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_X25519_HKDF_SHA256: u16 = 32;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_DHKEM_X448_HKDF_SHA512: u16 = 33;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_ML_KEM_1024: u16 = 66;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_ML_KEM_1024_P384: u16 = 81;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_ML_KEM_512: u16 = 64;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_ML_KEM_768: u16 = 65;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_ML_KEM_768_P256: u16 = 80;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_X25519_KYBER768_DRAFT00: u16 = 48;
    /// Exact identifier value declared by the schema.
    pub const HPKE_KEM_X_WING: u16 = 25722;
    /// Exact bytes value declared by the schema.
    pub const HPKE_KEY_SCHEDULE_LABEL_OVERHEAD: usize = 5;
    /// Exact bytes value declared by the schema.
    pub const HPKE_LABELED_CONTEXT_LIMIT: usize = 65536;
    /// Exact bytes value declared by the schema.
    pub const HPKE_MIN_PSK_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const HPKE_P256_PRIVATE_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const HPKE_P256_PUBLIC_KEY_LEN: usize = 65;
    /// Exact bytes value declared by the schema.
    pub const HPKE_P384_PRIVATE_KEY_LEN: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const HPKE_P384_PUBLIC_KEY_LEN: usize = 97;
    /// Exact bytes value declared by the schema.
    pub const HPKE_P521_PRIVATE_KEY_LEN: usize = 66;
    /// Exact bytes value declared by the schema.
    pub const HPKE_P521_PUBLIC_KEY_LEN: usize = 133;
    /// Exact bytes value declared by the schema.
    pub const HPKE_PRIVATE_KEY_MAX_LEN: usize = 66;
    /// Exact bytes value declared by the schema.
    pub const HPKE_PUBLIC_KEY_MAX_LEN: usize = 1665;
    /// Exact bytes value declared by the schema.
    pub const HPKE_SECP256K1_PRIVATE_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const HPKE_SECP256K1_PUBLIC_KEY_LEN: usize = 65;
    /// Exact bytes value declared by the schema.
    pub const HPKE_X25519_PRIVATE_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const HPKE_X25519_PUBLIC_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const HPKE_X448_PRIVATE_KEY_LEN: usize = 56;
    /// Exact bytes value declared by the schema.
    pub const HPKE_X448_PUBLIC_KEY_LEN: usize = 56;
}

/// Immutable `hpke_base_p256` contract constants.
pub mod hpke_base_p256 {
    /// Exact bytes value declared by the schema.
    pub const INFO_MAX_LEN: usize = 65530;
    /// Exact bytes value declared by the schema.
    pub const PLAINTEXT_MAX_LEN: usize = 16777216;
    /// Exact bytes value declared by the schema.
    pub const PRIVATE_KEY_LEN: usize = super::hpke::HPKE_P256_PRIVATE_KEY_LEN;
    /// Exact bytes value declared by the schema.
    pub const PUBLIC_KEY_LEN: usize = super::hpke::HPKE_P256_PUBLIC_KEY_LEN;
    /// Exact bytes value declared by the schema.
    pub const TAG_LEN: usize = super::hpke::HPKE_AEAD_TAG_LEN;
}

/// Immutable `hpke_internal` contract constants.
pub mod hpke_internal {
    /// Exact bytes value declared by the schema.
    pub const MIN_INPUT_KEY_MATERIAL_LEN: usize =
        super::operation_hpke::HPKE_OPERATION_MIN_INPUT_KEY_MATERIAL_LEN;
    /// Exact identifier value declared by the schema.
    pub const UNCOMPRESSED_POINT_PREFIX: u8 = 4;
}

/// Immutable `key_identifier` contract constants.
pub mod key_identifier {
    /// Exact bytes value declared by the schema.
    pub const SUBJECT_KEY_IDENTIFIER_LEN: usize = 20;
    /// Exact bytes value declared by the schema.
    pub const SUBJECT_PUBLIC_KEY_MAX_LEN: usize = 16384;
    /// Exact bytes value declared by the schema.
    pub const SUBJECT_PUBLIC_KEY_MIN_LEN: usize = 1;
}

/// Immutable `kmac` contract constants.
pub mod kmac {
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MAX_CONTEXT_LENGTH: usize = 65536;
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MAX_CUSTOMIZATION_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MAX_KEY_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MAX_OUTPUT_LENGTH: usize = 65536;
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MIN_CONTEXT_LENGTH: usize = 0;
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MIN_CUSTOMIZATION_LENGTH: usize = 0;
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MIN_KEY_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const KMAC256_MIN_OUTPUT_LENGTH: usize = 1;
}

/// Immutable `kotlin_native_status` contract constants.
pub mod kotlin_native_status {
    /// Exact identifier value declared by the schema.
    pub const KOTLIN_NATIVE_AUTHENTICATION_FAILED: i32 = 2;
    /// Exact identifier value declared by the schema.
    pub const KOTLIN_NATIVE_BACKEND_INTERNAL: i32 = 5;
    /// Exact identifier value declared by the schema.
    pub const KOTLIN_NATIVE_INVALID_INPUT: i32 = 1;
    /// Exact identifier value declared by the schema.
    pub const KOTLIN_NATIVE_INVALID_SIGNATURE: i32 = 6;
    /// Exact identifier value declared by the schema.
    pub const KOTLIN_NATIVE_OK: i32 = 0;
}

/// Immutable `ml_dsa_44` contract constants.
pub mod ml_dsa_44 {
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_44_SECRET_SEED_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_44_SIGNATURE_LEN: usize = 2420;
}

/// Immutable `ml_dsa_65` contract constants.
pub mod ml_dsa_65 {
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_65_SECRET_SEED_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
}

/// Immutable `ml_dsa_87` contract constants.
pub mod ml_dsa_87 {
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_87_SECRET_SEED_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;
}

/// Immutable `ml_kem_1024` contract constants.
pub mod ml_kem_1024 {
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_1024_ENCAPS_RANDOMNESS_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_1024_PUBLIC_KEY_LEN: usize = 1568;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_1024_SECRET_KEY_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_1024_SHARED_SECRET_LEN: usize = 32;
}

/// Immutable `ml_kem_512` contract constants.
pub mod ml_kem_512 {
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_512_CIPHERTEXT_LEN: usize = 768;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_512_ENCAPS_RANDOMNESS_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_512_PUBLIC_KEY_LEN: usize = 800;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_512_SECRET_KEY_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_512_SHARED_SECRET_LEN: usize = 32;
}

/// Immutable `ml_kem_768` contract constants.
pub mod ml_kem_768 {
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_768_ENCAPS_RANDOMNESS_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_768_SECRET_KEY_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;
}

/// Immutable `operation_hpke` contract constants.
pub mod operation_hpke {
    /// Exact bytes value declared by the schema.
    pub const HPKE_OPERATION_MIN_INPUT_KEY_MATERIAL_LEN: usize = 32;
}

/// Immutable `operation_signature` contract constants.
pub mod operation_signature {
    /// Exact bytes value declared by the schema.
    pub const SLH_DSA_DERIVE_INPUT_LEN: usize = 48;
}

/// Immutable `p256` contract constants.
pub mod p256 {
    /// Exact levels value declared by the schema.
    pub const DER_PAIR_DEPTH: usize = 1;
    /// Exact count value declared by the schema.
    pub const DER_PAIR_ELEMENTS: usize = 3;
    /// Exact bytes value declared by the schema.
    pub const P256_ECDSA_JOSE_SIGNATURE_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const P256_MAX_KEY_DER_LEN: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const P256_MAX_KEY_PEM_LEN: usize = 8192;
    /// Exact bytes value declared by the schema.
    pub const P256_MIN_KEY_DER_LEN: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const P256_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
    /// Exact bytes value declared by the schema.
    pub const P256_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;
    /// Exact bytes value declared by the schema.
    pub const P256_SECRET_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const P256_SHA256_DIGEST_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const P256_SHARED_SECRET_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const P256_SIGNATURE_DER_MAX_LEN: usize = 72;
    /// Exact bytes value declared by the schema.
    pub const SE_HANDLE_PREFIX: &[u8] = &[0x55, 0x30, 0x55, 0x36];
}

/// Immutable `p384` contract constants.
pub mod p384 {
    /// Exact bytes value declared by the schema.
    pub const P384_PUBLIC_KEY_COMPRESSED_LEN: usize = 49;
    /// Exact bytes value declared by the schema.
    pub const P384_PUBLIC_KEY_RAW_LEN: usize = 96;
    /// Exact bytes value declared by the schema.
    pub const P384_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 97;
    /// Exact bytes value declared by the schema.
    pub const P384_SECRET_KEY_LEN: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const P384_SHARED_SECRET_LEN: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const P384_SIGNATURE_DER_MAX_LEN: usize = 104;
}

/// Immutable `p521` contract constants.
pub mod p521 {
    /// Exact bytes value declared by the schema.
    pub const P521_PUBLIC_KEY_COMPRESSED_LEN: usize = 67;
    /// Exact bytes value declared by the schema.
    pub const P521_PUBLIC_KEY_RAW_LEN: usize = 132;
    /// Exact bytes value declared by the schema.
    pub const P521_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 133;
    /// Exact bytes value declared by the schema.
    pub const P521_SECRET_KEY_LEN: usize = 66;
    /// Exact bytes value declared by the schema.
    pub const P521_SHARED_SECRET_LEN: usize = 66;
    /// Exact bytes value declared by the schema.
    pub const P521_SIGNATURE_DER_MAX_LEN: usize = 144;
}

/// Immutable `pbkdf2` contract constants.
pub mod pbkdf2 {
    /// Exact evaluations value declared by the schema.
    pub const PBKDF2_MAX_HMAC_EVALUATIONS: u64 = 20000000;
    /// Exact iterations value declared by the schema.
    pub const PBKDF2_MAX_ITERATIONS: u32 = 10000000;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_MAX_OUTPUT_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_MAX_PASSWORD_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_MAX_SALT_LENGTH: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_MIN_OUTPUT_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_MIN_PASSWORD_LENGTH: usize = 1;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_MIN_SALT_LENGTH: usize = 1;
    /// Exact iterations value declared by the schema.
    pub const PBKDF2_MODERN_MIN_ITERATIONS: u32 = 100000;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_SHA256_OUTPUT_LENGTH: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const PBKDF2_SHA512_OUTPUT_LENGTH: usize = 64;
    /// Exact iterations value declared by the schema.
    pub const PBKDF2_STANDARD_MIN_ITERATIONS: u32 = 1;
}

/// Immutable `poseidon2` contract constants.
pub mod poseidon2 {
    /// Exact bytes value declared by the schema.
    pub const DIGEST_BYTES: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const MAX_INPUT_BYTES: usize = 515;
}

/// Immutable `prime_groups` contract constants.
pub mod prime_groups {
    /// Exact count value declared by the schema.
    pub const MAX_RANDOM_ATTEMPTS: usize = 128;
    /// Exact bytes value declared by the schema.
    pub const MAX_REDUCTION_BYTES: usize = 512;
}

/// Immutable `proto_wire` contract constants.
pub mod proto_wire {
    /// Exact identifier value declared by the schema.
    pub const BACKEND_REASON_CODE_MAX: i32 = 399;
    /// Exact identifier value declared by the schema.
    pub const BACKEND_REASON_CODE_MIN: i32 = 300;
    /// Exact bytes value declared by the schema.
    pub const CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT: usize = 1024;
    /// Exact levels value declared by the schema.
    pub const CRYPTO_PROTO_RECURSION_LIMIT: u32 = 64;
    /// Exact count value declared by the schema.
    pub const CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;
    /// Exact bytes value declared by the schema.
    pub const MAX_CRYPTO_PROTO_JSON_BYTES: usize = 1572864;
    /// Exact bytes value declared by the schema.
    pub const MAX_CRYPTO_PROTO_MESSAGE_BYTES: usize = 1048576;
    /// Exact identifier value declared by the schema.
    pub const PRIMITIVE_REASON_CODE_MAX: i32 = 199;
    /// Exact identifier value declared by the schema.
    pub const PRIMITIVE_REASON_CODE_MIN: i32 = 100;
    /// Exact identifier value declared by the schema.
    pub const PROVIDER_REASON_CODE_MAX: i32 = 299;
    /// Exact identifier value declared by the schema.
    pub const PROVIDER_REASON_CODE_MIN: i32 = 200;
}

/// Immutable `rsa` contract constants.
pub mod rsa {
    /// Exact bits value declared by the schema.
    pub const RSA_MAX_EXPONENT_BITS: usize = 64;
    /// Exact bits value declared by the schema.
    pub const RSA_MAX_MODULUS_BITS: usize = 8192;
    /// Exact bits value declared by the schema.
    pub const RSA_MIN_EXPONENT_BITS: usize = 2;
    /// Exact bits value declared by the schema.
    pub const RSA_MIN_MODULUS_BITS: usize = 1024;
    /// Exact bytes value declared by the schema.
    pub const RSA_PUBLIC_KEY_DER_MAX_LEN: usize = 4096;
    /// Exact bytes value declared by the schema.
    pub const RSA_SIGNATURE_MAX_LEN: usize = 1024;
}

/// Immutable `rsa_ffi` contract constants.
pub mod rsa_ffi {
    /// Exact identifier value declared by the schema.
    pub const RSA_DER_PKCS1_FFI_ID: u32 = 1;
    /// Exact identifier value declared by the schema.
    pub const RSA_DER_SPKI_FFI_ID: u32 = 2;
    /// Exact identifier value declared by the schema.
    pub const RSA_HASH_SHA1_FFI_ID: u32 = 1;
    /// Exact identifier value declared by the schema.
    pub const RSA_HASH_SHA256_FFI_ID: u32 = 2;
    /// Exact identifier value declared by the schema.
    pub const RSA_HASH_SHA384_FFI_ID: u32 = 3;
    /// Exact identifier value declared by the schema.
    pub const RSA_HASH_SHA512_FFI_ID: u32 = 4;
}

/// Immutable `secp256k1` contract constants.
pub mod secp256k1 {
    /// Exact bytes value declared by the schema.
    pub const BIP340_SCHNORR_AUX_RAND_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const BIP340_SCHNORR_MESSAGE_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const BIP340_SCHNORR_PUBLIC_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const BIP340_SCHNORR_SIGNATURE_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const DER_MAX_LEN_OCTETS: usize = 2;
    /// Exact bytes value declared by the schema.
    pub const SECP256K1_ECDSA_JOSE_SIGNATURE_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const SECP256K1_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;
    /// Exact bytes value declared by the schema.
    pub const SECP256K1_SECRET_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const SECP256K1_SHARED_SECRET_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN: usize = 65;
}

/// Immutable `sha2` contract constants.
pub mod sha2 {
    /// Exact bytes value declared by the schema.
    pub const SHA2_384_DIGEST_LENGTH: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const SHA2_512_DIGEST_LENGTH: usize = 64;
}

/// Immutable `sha2_256` contract constants.
pub mod sha2_256 {
    /// Exact bytes value declared by the schema.
    pub const SHA2_256_DIGEST_LENGTH: usize = 32;
}

/// Immutable `sha3` contract constants.
pub mod sha3 {
    /// Exact bytes value declared by the schema.
    pub const SHA3_224_DIGEST_LENGTH: usize = 28;
    /// Exact bytes value declared by the schema.
    pub const SHA3_384_DIGEST_LENGTH: usize = 48;
    /// Exact bytes value declared by the schema.
    pub const SHA3_512_DIGEST_LENGTH: usize = 64;
}

/// Immutable `sha3_256` contract constants.
pub mod sha3_256 {
    /// Exact bytes value declared by the schema.
    pub const SHA3_256_DIGEST_LENGTH: usize = 32;
}

/// Immutable `slh_dsa` contract constants.
pub mod slh_dsa {
    /// Exact count value declared by the schema.
    pub const SLH_DSA_KEYGEN_SEED_PART_COUNT: usize = 3;
    /// Exact bytes value declared by the schema.
    pub const SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN: usize = 16;
    /// Exact bytes value declared by the schema.
    pub const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const SLH_DSA_SHA2_128S_SECRET_KEY_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const SLH_DSA_SHA2_128S_SIGNATURE_LEN: usize = 7856;
}

/// Immutable `wasm_status` contract constants.
pub mod wasm_status {
    /// Exact identifier value declared by the schema.
    pub const WASM_ERROR_AUTHENTICATION_FAILED: u32 = 3;
    /// Exact identifier value declared by the schema.
    pub const WASM_ERROR_INVALID_INPUT: u32 = 1;
    /// Exact identifier value declared by the schema.
    pub const WASM_ERROR_INVALID_SIGNATURE: u32 = 2;
    /// Exact identifier value declared by the schema.
    pub const WASM_ERROR_PROVIDER_FAILURE: u32 = 4;
    /// Exact identifier value declared by the schema.
    pub const WASM_ERROR_UNSUPPORTED_ALGORITHM: u32 = 5;
}

/// Immutable `wasm_suite` contract constants.
pub mod wasm_suite {
    /// Exact identifier value declared by the schema.
    pub const HPKE_SUITE_P256_SHA256_AES256GCM: u32 = 1;
    /// Exact identifier value declared by the schema.
    pub const HPKE_SUITE_X25519_SHA256_CHACHA20POLY1305: u32 = 2;
}

/// Immutable `x25519` contract constants.
pub mod x25519 {
    /// Exact bytes value declared by the schema.
    pub const X25519_PRIVATE_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const X25519_PUBLIC_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const X25519_SHARED_SECRET_LEN: usize = 32;
}

/// Immutable `x448` contract constants.
pub mod x448 {
    /// Exact bytes value declared by the schema.
    pub const X448_PRIVATE_KEY_LEN: usize = 56;
    /// Exact bytes value declared by the schema.
    pub const X448_PUBLIC_KEY_LEN: usize = 56;
    /// Exact bytes value declared by the schema.
    pub const X448_SHARED_SECRET_LEN: usize = 56;
}

/// Immutable `x_wing` contract constants.
pub mod x_wing {
    /// Exact bytes value declared by the schema.
    pub const X_WING_768_CIPHERTEXT_LEN: usize = 1120;
    /// Exact bytes value declared by the schema.
    pub const X_WING_768_PUBLIC_KEY_LEN: usize = 1216;
    /// Exact bytes value declared by the schema.
    pub const X_WING_ENCAPS_SEED_LEN: usize = 64;
    /// Exact bytes value declared by the schema.
    pub const X_WING_SECRET_KEY_LEN: usize = 32;
    /// Exact bytes value declared by the schema.
    pub const X_WING_SHARED_SECRET_LEN: usize = 32;
}
