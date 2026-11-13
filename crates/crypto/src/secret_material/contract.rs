// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Query native ownership policy without accepting caller policy overrides.

use crypto_core::{CryptoError, RngOutputKind};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoMaterialPolicyQueryRequest, CryptoRandomFillPolicyQueryRequest,
    OperationSecretMaterialPolicy,
};

use super::{
    operation_secret_material_policy, random_fill_secret_material_policy, SecretMaterialOperation,
};

/// Report the exact policy already enforced by this semantic operation.
pub fn operation_policy(
    request: &CryptoMaterialPolicyQueryRequest,
) -> Result<OperationSecretMaterialPolicy, CryptoError> {
    require_known(request.__buffa_unknown_fields.is_empty())?;
    Ok(
        operation_secret_material_policy(SecretMaterialOperation::try_from(request.operation)?)
            .into(),
    )
}

/// Report purpose-specific random fill policy without selecting an RNG provider.
pub fn random_fill_policy(
    request: &CryptoRandomFillPolicyQueryRequest,
) -> Result<OperationSecretMaterialPolicy, CryptoError> {
    require_known(request.__buffa_unknown_fields.is_empty())?;
    Ok(random_fill_secret_material_policy(RngOutputKind::try_from(request.purpose)?).into())
}

fn require_known(known: bool) -> Result<(), CryptoError> {
    if known {
        Ok(())
    } else {
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    }
}
