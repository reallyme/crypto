// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Minimum password/secret input length accepted by the primitive.
pub const PBKDF2_MIN_PASSWORD_LENGTH: usize = 1;
/// Maximum password/secret input length accepted by the primitive.
pub const PBKDF2_MAX_PASSWORD_LENGTH: usize = 4096;
/// Minimum salt length accepted by the primitive.
///
/// RFC 6070 test vectors use short salts, so the standards-level primitive
/// accepts them. Higher-level protocols must enforce their public policy.
pub const PBKDF2_MIN_SALT_LENGTH: usize = 1;
/// Maximum salt length accepted by the primitive.
pub const PBKDF2_MAX_SALT_LENGTH: usize = 4096;
/// Minimum iteration count accepted by the RFC 8018 primitive.
pub const PBKDF2_STANDARD_MIN_ITERATIONS: u32 = 1;
/// Minimum iteration count recommended for new public PBKDF2 policy profiles.
pub const PBKDF2_MODERN_MIN_ITERATIONS: u32 = 100_000;
/// Maximum iteration count accepted by PBKDF2 derivation routes.
///
/// This ceiling bounds attacker-selected CPU work at public protocol and FFI
/// boundaries while retaining substantial headroom above current reviewed
/// password-storage recommendations.
pub const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;
/// Minimum derived output length in bytes.
pub const PBKDF2_MIN_OUTPUT_LENGTH: usize = 1;
/// Maximum derived output length in bytes.
pub const PBKDF2_MAX_OUTPUT_LENGTH: usize = 4096;
