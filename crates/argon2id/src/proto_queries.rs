// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema-backed admission queries for the unchanged fixed Argon2id profiles.

use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2ParamsProfile as ProtoParams, CryptoArgon2BudgetFitRequest,
    CryptoArgon2MobileUnlockRequest, CryptoArgon2PlatformResolveRequest,
    CryptoArgon2idProfileIdentifier,
};

use crate::{
    resolve_mobile_profile_for_unlock, resolve_profile_params_for_platform,
    resolve_profile_params_with_caps, Argon2Caps, Argon2KdfVersion, Argon2PlatformClass,
};

/// Resolves the requested fixed profile under the platform's existing caps.
/// No derivation or provider selection is performed by this query.
pub fn resolve_platform(
    request: &CryptoArgon2PlatformResolveRequest,
) -> Result<ProtoParams, CryptoError> {
    require_known(request.__buffa_unknown_fields.is_empty())?;
    let version = version_number(request.profile.as_option())?;
    let platform = Argon2PlatformClass::try_from(request.platform)?;
    Ok(resolve_profile_params_for_platform(version, platform)?.into())
}

/// Reports the fixed cost tuple only when it fits all explicitly supplied
/// resource budgets. A successful query does not authorize a provider or
/// override the fixed derivation profile or platform policy.
pub fn resolve_budget(request: &CryptoArgon2BudgetFitRequest) -> Result<ProtoParams, CryptoError> {
    require_known(request.__buffa_unknown_fields.is_empty())?;
    let version = version_number(request.profile.as_option())?;
    let caps = Argon2Caps {
        mem_cap_kib: request
            .memory_limit_kib
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        time_cost_cap: request
            .time_cost_limit
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        lanes_cap: request
            .lanes_limit
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    };
    Ok(resolve_profile_params_with_caps(version, caps)?.into())
}

/// Selects the existing modern-mobile unlock profile without caller policy.
pub fn select_mobile_unlock(
    request: &CryptoArgon2MobileUnlockRequest,
) -> Result<CryptoArgon2idProfileIdentifier, CryptoError> {
    require_known(request.__buffa_unknown_fields.is_empty())?;
    Ok(resolve_mobile_profile_for_unlock()?.into())
}

fn version_number(profile: Option<&CryptoArgon2idProfileIdentifier>) -> Result<u32, CryptoError> {
    let profile = profile.ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    // The existing total identity bridge rejects unknown versions/modifiers.
    // Read the accepted schema number rather than restating its wire identity.
    let _version = Argon2KdfVersion::try_from(profile)?;
    u32::try_from(profile.kdf_version.to_i32())
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_PARAMETER)
}

fn require_known(known: bool) -> Result<(), CryptoError> {
    if known {
        Ok(())
    } else {
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    }
}
