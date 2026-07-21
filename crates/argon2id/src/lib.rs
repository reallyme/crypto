// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Argon2id password/key derivation with code-pinned cost profiles. Platform resource caps are enforced before derivation and derived material is zeroized.

#![forbid(unsafe_code)]

mod constants;
mod derive;
mod material;
mod profile;

pub use constants::{
    ARGON2ID_DERIVED_KEY_LENGTH, ARGON2ID_SALT_MAX_LENGTH, ARGON2ID_SALT_MIN_LENGTH,
    ARGON2ID_SECRET_MAX_LENGTH, ARGON2ID_V1_LANES, ARGON2ID_V1_MEMORY_COST_KIB,
    ARGON2ID_V1_TIME_COST, ARGON2ID_V2_LANES, ARGON2ID_V2_MEMORY_COST_KIB, ARGON2ID_V2_TIME_COST,
};
pub use derive::{derive_key, derive_key_for_version, DeriveKeyRequest};
pub use material::{Argon2Salt, Argon2Secret, Argon2idDerivedKey};
pub use profile::{
    resolve_mobile_profile_for_unlock, resolve_profile_params_for_platform,
    resolve_profile_params_with_caps, Argon2Caps, Argon2KdfVersion, Argon2ParamsProfile,
    Argon2PlatformClass, Argon2Profile,
};
