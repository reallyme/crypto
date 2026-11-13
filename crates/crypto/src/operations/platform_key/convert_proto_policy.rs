// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema policy descriptors preserve native policy and never authorize execution.

use super::PlatformKeyOperation;
use buffa::EnumValue;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::PlatformKeyOperation as ProtoPlatformKeyOperation;

impl TryFrom<EnumValue<ProtoPlatformKeyOperation>> for PlatformKeyOperation {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoPlatformKeyOperation>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoPlatformKeyOperation::PLATFORM_KEY_OPERATION_GENERATE) => Ok(Self::Generate),
            Some(ProtoPlatformKeyOperation::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY) => {
                Ok(Self::GetPublicKey)
            }
            Some(ProtoPlatformKeyOperation::PLATFORM_KEY_OPERATION_SIGN) => Ok(Self::Sign),
            Some(ProtoPlatformKeyOperation::PLATFORM_KEY_OPERATION_VERIFY) => Ok(Self::Verify),
            Some(ProtoPlatformKeyOperation::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET) => {
                Ok(Self::DeriveSharedSecret)
            }
            Some(ProtoPlatformKeyOperation::PLATFORM_KEY_OPERATION_DELETE) => Ok(Self::Delete),
            Some(ProtoPlatformKeyOperation::PLATFORM_KEY_OPERATION_ATTEST) => Ok(Self::Attest),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<PlatformKeyOperation> for ProtoPlatformKeyOperation {
    fn from(value: PlatformKeyOperation) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            PlatformKeyOperation::Generate => Self::PLATFORM_KEY_OPERATION_GENERATE,
            PlatformKeyOperation::GetPublicKey => Self::PLATFORM_KEY_OPERATION_GET_PUBLIC_KEY,
            PlatformKeyOperation::Sign => Self::PLATFORM_KEY_OPERATION_SIGN,
            PlatformKeyOperation::Verify => Self::PLATFORM_KEY_OPERATION_VERIFY,
            PlatformKeyOperation::DeriveSharedSecret => {
                Self::PLATFORM_KEY_OPERATION_DERIVE_SHARED_SECRET
            }
            PlatformKeyOperation::Delete => Self::PLATFORM_KEY_OPERATION_DELETE,
            PlatformKeyOperation::Attest => Self::PLATFORM_KEY_OPERATION_ATTEST,
        }
    }
}
