// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Minimum password/secret input length accepted by the primitive.
pub const PBKDF2_MIN_PASSWORD_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MIN_PASSWORD_LENGTH;
/// Maximum password/secret input length accepted by the primitive.
pub const PBKDF2_MAX_PASSWORD_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MAX_PASSWORD_LENGTH;
/// Minimum salt length accepted by the primitive.
///
/// RFC 6070 test vectors use short salts, so the standards-level primitive
/// accepts them. Higher-level protocols must enforce their public policy.
pub const PBKDF2_MIN_SALT_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MIN_SALT_LENGTH;
/// Maximum salt length accepted by the primitive.
pub const PBKDF2_MAX_SALT_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MAX_SALT_LENGTH;
/// Minimum iteration count accepted by the RFC 8018 primitive.
pub const PBKDF2_STANDARD_MIN_ITERATIONS: u32 =
    crypto_core::contract_constants::pbkdf2::PBKDF2_STANDARD_MIN_ITERATIONS;
/// Minimum iteration count recommended for new public PBKDF2 policy profiles.
pub const PBKDF2_MODERN_MIN_ITERATIONS: u32 =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS;
/// Maximum iteration count accepted by PBKDF2 derivation routes.
///
/// This ceiling bounds attacker-selected CPU work at public protocol and FFI
/// boundaries while retaining substantial headroom above current reviewed
/// password-storage recommendations.
pub const PBKDF2_MAX_ITERATIONS: u32 =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MAX_ITERATIONS;
/// Minimum derived output length in bytes.
pub const PBKDF2_MIN_OUTPUT_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MIN_OUTPUT_LENGTH;
/// Maximum derived output length in bytes.
pub const PBKDF2_MAX_OUTPUT_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MAX_OUTPUT_LENGTH;
/// Limit total HMAC evaluations, since output blocks multiply iteration work.
#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) const PBKDF2_MAX_HMAC_EVALUATIONS: u64 =
    crypto_core::contract_constants::pbkdf2::PBKDF2_MAX_HMAC_EVALUATIONS;
#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) const PBKDF2_SHA256_OUTPUT_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_SHA256_OUTPUT_LENGTH;
#[cfg(any(feature = "native", feature = "wasm"))]
pub(crate) const PBKDF2_SHA512_OUTPUT_LENGTH: usize =
    crypto_core::contract_constants::pbkdf2::PBKDF2_SHA512_OUTPUT_LENGTH;
