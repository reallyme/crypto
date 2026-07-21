// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};

use crate::constants::{
    ARGON2ID_V1_LANES, ARGON2ID_V1_MEMORY_COST_KIB, ARGON2ID_V1_TIME_COST, ARGON2ID_V2_LANES,
    ARGON2ID_V2_MEMORY_COST_KIB, ARGON2ID_V2_TIME_COST,
};

/// Named Argon2id parameter profile selecting a fixed cost tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Argon2Profile {
    /// First-generation profile.
    V1,
    /// Second-generation profile (higher memory cost).
    V2,
}

/// Wire/versioning tag for an Argon2id profile, encoded as its integer value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Argon2KdfVersion {
    /// Version 1 (integer value `1`).
    V1 = 1,
    /// Version 2 (integer value `2`).
    V2 = 2,
}

/// Platform class used to select resource caps for parameter validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Argon2PlatformClass {
    /// A modern mobile device (tighter memory/time caps).
    MobileModern,
    /// A modern desktop device (higher memory/time caps).
    DesktopModern,
}

/// Upper bounds on Argon2id cost parameters permitted on a given platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Argon2Caps {
    /// Maximum memory cost in KiB.
    pub mem_cap_kib: u32,
    /// Maximum time cost (number of passes).
    pub time_cost_cap: u32,
    /// Maximum degree of parallelism (lanes).
    pub lanes_cap: u32,
}

/// Concrete Argon2id cost parameters resolved from a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Argon2ParamsProfile {
    /// Memory cost in KiB.
    pub mem_kib: u32,
    /// Time cost (number of passes).
    pub time_cost: u32,
    /// Degree of parallelism (lanes).
    pub lanes: u32,
}

impl Argon2Caps {
    /// Returns the resource caps associated with the given platform class.
    pub const fn for_platform(platform: Argon2PlatformClass) -> Self {
        match platform {
            Argon2PlatformClass::MobileModern => Self {
                mem_cap_kib: 524_288,
                time_cost_cap: 4,
                lanes_cap: 4,
            },
            Argon2PlatformClass::DesktopModern => Self {
                mem_cap_kib: 2_097_152,
                time_cost_cap: 6,
                lanes_cap: 4,
            },
        }
    }
}

impl TryFrom<u32> for Argon2KdfVersion {
    type Error = CryptoError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(CryptoError::Kdf {
                algorithm: KdfAlgorithm::Argon2id,
                profile: KdfProfile::Argon2idV1,
                kind: KdfFailureKind::InvalidParams,
            }),
        }
    }
}

impl From<Argon2KdfVersion> for Argon2Profile {
    fn from(value: Argon2KdfVersion) -> Self {
        match value {
            Argon2KdfVersion::V1 => Self::V1,
            Argon2KdfVersion::V2 => Self::V2,
        }
    }
}

impl Argon2Profile {
    /// Maps this profile to its `crypto_core` [`KdfProfile`] tag.
    pub const fn to_kdf_profile(self) -> KdfProfile {
        match self {
            Self::V1 => KdfProfile::Argon2idV1,
            Self::V2 => KdfProfile::Argon2idV2,
        }
    }

    const fn params(self) -> Argon2ParamsProfile {
        match self {
            Self::V1 => Argon2ParamsProfile {
                mem_kib: ARGON2ID_V1_MEMORY_COST_KIB,
                time_cost: ARGON2ID_V1_TIME_COST,
                lanes: ARGON2ID_V1_LANES,
            },
            Self::V2 => Argon2ParamsProfile {
                mem_kib: ARGON2ID_V2_MEMORY_COST_KIB,
                time_cost: ARGON2ID_V2_TIME_COST,
                lanes: ARGON2ID_V2_LANES,
            },
        }
    }

    pub(crate) const fn params_tuple(self) -> (u32, u32, u32) {
        let params = self.params();
        (params.mem_kib, params.time_cost, params.lanes)
    }
}

fn validate_caps(
    profile: Argon2Profile,
    caps: Argon2Caps,
) -> Result<Argon2ParamsProfile, CryptoError> {
    let params = profile.params();
    let profile_tag = profile.to_kdf_profile();

    if params.mem_kib > caps.mem_cap_kib
        || params.time_cost > caps.time_cost_cap
        || params.lanes > caps.lanes_cap
    {
        return Err(CryptoError::Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            profile: profile_tag,
            kind: KdfFailureKind::InvalidParams,
        });
    }

    Ok(params)
}

/// Resolves the cost parameters for the given KDF version and validates them
/// against the platform's caps. Returns an error if the version is unrecognized
/// or the profile's parameters exceed the platform caps.
pub fn resolve_profile_params_for_platform(
    kdf_version: u32,
    platform: Argon2PlatformClass,
) -> Result<Argon2ParamsProfile, CryptoError> {
    let version = Argon2KdfVersion::try_from(kdf_version)?;
    let profile = Argon2Profile::from(version);
    validate_caps(profile, Argon2Caps::for_platform(platform))
}

/// Resolves the cost parameters for the given KDF version and validates them
/// against explicit caps. Returns an error if the version is unrecognized or the
/// profile's parameters exceed the supplied caps.
pub fn resolve_profile_params_with_caps(
    kdf_version: u32,
    caps: Argon2Caps,
) -> Result<Argon2ParamsProfile, CryptoError> {
    let version = Argon2KdfVersion::try_from(kdf_version)?;
    let profile = Argon2Profile::from(version);
    validate_caps(profile, caps)
}

/// Selects the strongest Argon2id version whose parameters fit within modern
/// mobile caps for an unlock operation: prefers V2, falling back to V1. Returns
/// an error only if neither version's parameters fit.
pub fn resolve_mobile_profile_for_unlock() -> Result<Argon2KdfVersion, CryptoError> {
    let preferred = Argon2KdfVersion::V2;
    let profile = Argon2Profile::from(preferred);
    let caps = Argon2Caps::for_platform(Argon2PlatformClass::MobileModern);

    if validate_caps(profile, caps).is_ok() {
        return Ok(preferred);
    }

    let fallback = Argon2KdfVersion::V1;
    let fallback_profile = Argon2Profile::from(fallback);
    validate_caps(fallback_profile, caps)?;
    Ok(fallback)
}
