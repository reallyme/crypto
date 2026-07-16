// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Minimum password/secret input length accepted by the primitive.
pub const PBKDF2_MIN_PASSWORD_LENGTH: usize = 1;
/// Maximum password/secret input length accepted by the primitive.
pub const PBKDF2_MAX_PASSWORD_LENGTH: usize = 4096;
/// Minimum salt length accepted by the primitive.
///
/// RFC 6070 and legacy systems use short salts, so the primitive accepts them
/// for compatibility. Higher-level protocols should enforce modern policy.
pub const PBKDF2_MIN_SALT_LENGTH: usize = 1;
/// Maximum salt length accepted by the primitive.
pub const PBKDF2_MAX_SALT_LENGTH: usize = 4096;
/// Minimum iteration count accepted by the primitive.
pub const PBKDF2_MIN_ITERATIONS: u32 = 1;
/// Minimum derived output length in bytes.
pub const PBKDF2_MIN_OUTPUT_LENGTH: usize = 1;
/// Maximum derived output length in bytes.
pub const PBKDF2_MAX_OUTPUT_LENGTH: usize = 4096;
