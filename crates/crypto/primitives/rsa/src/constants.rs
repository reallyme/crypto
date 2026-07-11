// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Minimum RSA modulus accepted for legacy verification.
///
/// eMRTD deployments still contain 1024-bit RSA material. New signing profiles
/// should require stronger keys at their protocol layer.
pub const RSA_MIN_MODULUS_BITS: usize = 1024;

/// Maximum RSA modulus accepted by this primitive to bound CPU and allocation.
pub const RSA_MAX_MODULUS_BITS: usize = 8192;

/// Minimum accepted RSA public exponent size.
pub(crate) const RSA_MIN_EXPONENT_BITS: usize = 2;

/// Maximum accepted RSA public exponent size.
///
/// Public exponents in deployed RSA certificate material are normally small
/// values such as 65537. Bounding this public field avoids accidental
/// verifier-side denial of service from pathological keys.
pub(crate) const RSA_MAX_EXPONENT_BITS: usize = 64;

/// Maximum accepted DER public-key input length.
pub const RSA_PUBLIC_KEY_DER_MAX_LEN: usize = 4096;

/// Maximum accepted raw RSA signature length, matching an 8192-bit modulus.
pub const RSA_SIGNATURE_MAX_LEN: usize = RSA_MAX_MODULUS_BITS / 8;
