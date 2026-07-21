// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Length in bytes of the Argon2id-derived key output (32 bytes).
pub const ARGON2ID_DERIVED_KEY_LENGTH: usize = 32;
/// Maximum accepted secret length in bytes (one mebibyte).
pub const ARGON2ID_SECRET_MAX_LENGTH: usize = 1_048_576;
/// Minimum accepted salt length in bytes (16 bytes).
pub const ARGON2ID_SALT_MIN_LENGTH: usize = 16;
/// Maximum accepted salt length in bytes (32 bytes).
pub const ARGON2ID_SALT_MAX_LENGTH: usize = 32;
/// V1 profile memory cost in KiB (262,144 KiB = 256 MiB).
pub const ARGON2ID_V1_MEMORY_COST_KIB: u32 = 262_144;
/// V1 profile time cost (number of passes).
pub const ARGON2ID_V1_TIME_COST: u32 = 3;
/// V1 profile degree of parallelism (lanes).
pub const ARGON2ID_V1_LANES: u32 = 1;
/// V2 profile memory cost in KiB (524,288 KiB = 512 MiB).
pub const ARGON2ID_V2_MEMORY_COST_KIB: u32 = 524_288;
/// V2 profile time cost (number of passes).
pub const ARGON2ID_V2_TIME_COST: u32 = 3;
/// V2 profile degree of parallelism (lanes).
pub const ARGON2ID_V2_LANES: u32 = 1;
