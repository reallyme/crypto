// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema policy descriptors preserve native policy and never authorize execution.

use super::{
    BufferOwner, DestructionPolicy, ExportPolicy, MaterialPolicy, OperationSecretMaterialPolicy,
    OutputMaterial, RetentionPolicy, SecretMaterialOperation, SecretSensitivity, ZeroizationPolicy,
};
use buffa::EnumValue;
use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    BufferOwner as ProtoBufferOwner, DestructionPolicy as ProtoDestructionPolicy,
    ExportPolicy as ProtoExportPolicy, OutputMaterial as ProtoOutputMaterial,
    RetentionPolicy as ProtoRetentionPolicy,
    SecretMaterialOperation as ProtoSecretMaterialOperation,
    SecretSensitivity as ProtoSecretSensitivity, ZeroizationPolicy as ProtoZeroizationPolicy,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    MaterialPolicy as ProtoMaterialPolicy,
    OperationSecretMaterialPolicy as ProtoOperationSecretMaterialPolicy,
};

impl TryFrom<EnumValue<ProtoBufferOwner>> for BufferOwner {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoBufferOwner>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoBufferOwner::BUFFER_OWNER_CALLER) => Ok(Self::Caller),
            Some(ProtoBufferOwner::BUFFER_OWNER_OPERATION_LAYER) => Ok(Self::OperationLayer),
            Some(ProtoBufferOwner::BUFFER_OWNER_OPERATION_CONTRACT) => Ok(Self::OperationContract),
            Some(ProtoBufferOwner::BUFFER_OWNER_NATIVE_ADAPTER) => Ok(Self::NativeAdapter),
            Some(ProtoBufferOwner::BUFFER_OWNER_MANAGED_RUNTIME) => Ok(Self::ManagedRuntime),
            Some(ProtoBufferOwner::BUFFER_OWNER_PLATFORM_PROVIDER) => Ok(Self::PlatformProvider),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<BufferOwner> for ProtoBufferOwner {
    fn from(value: BufferOwner) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            BufferOwner::Caller => Self::BUFFER_OWNER_CALLER,
            BufferOwner::OperationLayer => Self::BUFFER_OWNER_OPERATION_LAYER,
            BufferOwner::OperationContract => Self::BUFFER_OWNER_OPERATION_CONTRACT,
            BufferOwner::NativeAdapter => Self::BUFFER_OWNER_NATIVE_ADAPTER,
            BufferOwner::ManagedRuntime => Self::BUFFER_OWNER_MANAGED_RUNTIME,
            BufferOwner::PlatformProvider => Self::BUFFER_OWNER_PLATFORM_PROVIDER,
        }
    }
}

impl TryFrom<EnumValue<ProtoSecretSensitivity>> for SecretSensitivity {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoSecretSensitivity>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoSecretSensitivity::SECRET_SENSITIVITY_PUBLIC) => Ok(Self::Public),
            Some(ProtoSecretSensitivity::SECRET_SENSITIVITY_SENSITIVE) => Ok(Self::Sensitive),
            Some(ProtoSecretSensitivity::SECRET_SENSITIVITY_SECRET) => Ok(Self::Secret),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<SecretSensitivity> for ProtoSecretSensitivity {
    fn from(value: SecretSensitivity) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            SecretSensitivity::Public => Self::SECRET_SENSITIVITY_PUBLIC,
            SecretSensitivity::Sensitive => Self::SECRET_SENSITIVITY_SENSITIVE,
            SecretSensitivity::Secret => Self::SECRET_SENSITIVITY_SECRET,
        }
    }
}

impl TryFrom<EnumValue<ProtoOutputMaterial>> for OutputMaterial {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoOutputMaterial>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoOutputMaterial::OUTPUT_MATERIAL_PUBLIC) => Ok(Self::Public),
            Some(ProtoOutputMaterial::OUTPUT_MATERIAL_SENSITIVE_PUBLIC) => {
                Ok(Self::SensitivePublic)
            }
            Some(ProtoOutputMaterial::OUTPUT_MATERIAL_SECRET) => Ok(Self::Secret),
            Some(ProtoOutputMaterial::OUTPUT_MATERIAL_MIXED) => Ok(Self::Mixed),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<OutputMaterial> for ProtoOutputMaterial {
    fn from(value: OutputMaterial) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            OutputMaterial::Public => Self::OUTPUT_MATERIAL_PUBLIC,
            OutputMaterial::SensitivePublic => Self::OUTPUT_MATERIAL_SENSITIVE_PUBLIC,
            OutputMaterial::Secret => Self::OUTPUT_MATERIAL_SECRET,
            OutputMaterial::Mixed => Self::OUTPUT_MATERIAL_MIXED,
        }
    }
}

impl TryFrom<EnumValue<ProtoRetentionPolicy>> for RetentionPolicy {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoRetentionPolicy>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoRetentionPolicy::RETENTION_POLICY_BORROWED_FOR_CALL) => {
                Ok(Self::BorrowedForCall)
            }
            Some(ProtoRetentionPolicy::RETENTION_POLICY_OPERATION_TEMPORARY) => {
                Ok(Self::OperationTemporary)
            }
            Some(ProtoRetentionPolicy::RETENTION_POLICY_RESULT_LIFETIME) => {
                Ok(Self::ResultLifetime)
            }
            Some(ProtoRetentionPolicy::RETENTION_POLICY_PROVIDER_MANAGED) => {
                Ok(Self::ProviderManaged)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<RetentionPolicy> for ProtoRetentionPolicy {
    fn from(value: RetentionPolicy) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            RetentionPolicy::BorrowedForCall => Self::RETENTION_POLICY_BORROWED_FOR_CALL,
            RetentionPolicy::OperationTemporary => Self::RETENTION_POLICY_OPERATION_TEMPORARY,
            RetentionPolicy::ResultLifetime => Self::RETENTION_POLICY_RESULT_LIFETIME,
            RetentionPolicy::ProviderManaged => Self::RETENTION_POLICY_PROVIDER_MANAGED,
        }
    }
}

impl TryFrom<EnumValue<ProtoExportPolicy>> for ExportPolicy {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoExportPolicy>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoExportPolicy::EXPORT_POLICY_PUBLIC) => Ok(Self::Public),
            Some(ProtoExportPolicy::EXPORT_POLICY_SECRET_OWNER_REQUIRED) => {
                Ok(Self::SecretOwnerRequired)
            }
            Some(ProtoExportPolicy::EXPORT_POLICY_NON_EXPORTABLE) => Ok(Self::NonExportable),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ExportPolicy> for ProtoExportPolicy {
    fn from(value: ExportPolicy) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ExportPolicy::Public => Self::EXPORT_POLICY_PUBLIC,
            ExportPolicy::SecretOwnerRequired => Self::EXPORT_POLICY_SECRET_OWNER_REQUIRED,
            ExportPolicy::NonExportable => Self::EXPORT_POLICY_NON_EXPORTABLE,
        }
    }
}

impl TryFrom<EnumValue<ProtoZeroizationPolicy>> for ZeroizationPolicy {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoZeroizationPolicy>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoZeroizationPolicy::ZEROIZATION_POLICY_NOT_REQUIRED) => Ok(Self::NotRequired),
            Some(ProtoZeroizationPolicy::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP) => {
                Ok(Self::OwnerZeroizesOnDrop)
            }
            Some(ProtoZeroizationPolicy::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY) => {
                Ok(Self::CallerRetainsResponsibility)
            }
            Some(ProtoZeroizationPolicy::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT) => {
                Ok(Self::ManagedRuntimeBestEffort)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<ZeroizationPolicy> for ProtoZeroizationPolicy {
    fn from(value: ZeroizationPolicy) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            ZeroizationPolicy::NotRequired => Self::ZEROIZATION_POLICY_NOT_REQUIRED,
            ZeroizationPolicy::OwnerZeroizesOnDrop => {
                Self::ZEROIZATION_POLICY_OWNER_ZEROIZES_ON_DROP
            }
            ZeroizationPolicy::CallerRetainsResponsibility => {
                Self::ZEROIZATION_POLICY_CALLER_RETAINS_RESPONSIBILITY
            }
            ZeroizationPolicy::ManagedRuntimeBestEffort => {
                Self::ZEROIZATION_POLICY_MANAGED_RUNTIME_BEST_EFFORT
            }
        }
    }
}

impl TryFrom<EnumValue<ProtoDestructionPolicy>> for DestructionPolicy {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoDestructionPolicy>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoDestructionPolicy::DESTRUCTION_POLICY_NONE_REQUIRED) => {
                Ok(Self::NoneRequired)
            }
            Some(ProtoDestructionPolicy::DESTRUCTION_POLICY_ZEROIZE_ON_DROP) => {
                Ok(Self::ZeroizeOnDrop)
            }
            Some(ProtoDestructionPolicy::DESTRUCTION_POLICY_CALLER_CONTROLLED) => {
                Ok(Self::CallerControlled)
            }
            Some(ProtoDestructionPolicy::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT) => {
                Ok(Self::ManagedRuntimeBestEffort)
            }
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<DestructionPolicy> for ProtoDestructionPolicy {
    fn from(value: DestructionPolicy) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            DestructionPolicy::NoneRequired => Self::DESTRUCTION_POLICY_NONE_REQUIRED,
            DestructionPolicy::ZeroizeOnDrop => Self::DESTRUCTION_POLICY_ZEROIZE_ON_DROP,
            DestructionPolicy::CallerControlled => Self::DESTRUCTION_POLICY_CALLER_CONTROLLED,
            DestructionPolicy::ManagedRuntimeBestEffort => {
                Self::DESTRUCTION_POLICY_MANAGED_RUNTIME_BEST_EFFORT
            }
        }
    }
}

impl TryFrom<EnumValue<ProtoSecretMaterialOperation>> for SecretMaterialOperation {
    type Error = CryptoError;

    fn try_from(value: EnumValue<ProtoSecretMaterialOperation>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_AEAD_SEAL) => Ok(Self::AeadSeal),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_AEAD_OPEN) => Ok(Self::AeadOpen),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE) => Ok(Self::ConstantTimeCompare),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HASH) => Ok(Self::Hash),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE) => Ok(Self::MacAuthenticate),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_MAC_VERIFY) => Ok(Self::MacVerify),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEY_DERIVATION) => Ok(Self::KeyDerivation),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEY_WRAP) => Ok(Self::KeyWrap),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEY_UNWRAP) => Ok(Self::KeyUnwrap),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION) => Ok(Self::SignatureKeyGeneration),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION) => Ok(Self::SignatureKeyDerivation),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN) => Ok(Self::SignatureSign),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY) => Ok(Self::SignatureVerify),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING) => Ok(Self::SignatureEncoding),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION) => Ok(Self::KeyAgreementKeyGeneration),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION) => Ok(Self::KeyAgreementKeyDerivation),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET) => Ok(Self::KeyAgreementSharedSecret),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION) => Ok(Self::KemKeyGeneration),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION) => Ok(Self::KemKeyDerivation),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE) => Ok(Self::KemEncapsulate),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE) => Ok(Self::KemDecapsulate),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION) => Ok(Self::HpkeKeyGeneration),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION) => Ok(Self::HpkeKeyDerivation),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP) => Ok(Self::HpkeSenderSetup),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP) => Ok(Self::HpkeReceiverSetup),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HPKE_SEAL) => Ok(Self::HpkeSeal),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HPKE_OPEN) => Ok(Self::HpkeOpen),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_HPKE_EXPORT) => Ok(Self::HpkeExport),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_RANDOM_FILL) => Ok(Self::RandomFill),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_RANDOM_NONCE) => Ok(Self::RandomNonce),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_RANDOM_SALT) => Ok(Self::RandomSalt),
            Some(ProtoSecretMaterialOperation::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING) => Ok(Self::PublicKeyEncoding),
            // Zero and unknown future values cannot silently select a policy.
            _ => Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
    }
}

impl From<SecretMaterialOperation> for ProtoSecretMaterialOperation {
    fn from(value: SecretMaterialOperation) -> Self {
        // Keep this exhaustive so new native variants require a schema decision.
        match value {
            SecretMaterialOperation::AeadSeal => Self::SECRET_MATERIAL_OPERATION_AEAD_SEAL,
            SecretMaterialOperation::AeadOpen => Self::SECRET_MATERIAL_OPERATION_AEAD_OPEN,
            SecretMaterialOperation::ConstantTimeCompare => {
                Self::SECRET_MATERIAL_OPERATION_CONSTANT_TIME_COMPARE
            }
            SecretMaterialOperation::Hash => Self::SECRET_MATERIAL_OPERATION_HASH,
            SecretMaterialOperation::MacAuthenticate => {
                Self::SECRET_MATERIAL_OPERATION_MAC_AUTHENTICATE
            }
            SecretMaterialOperation::MacVerify => Self::SECRET_MATERIAL_OPERATION_MAC_VERIFY,
            SecretMaterialOperation::KeyDerivation => {
                Self::SECRET_MATERIAL_OPERATION_KEY_DERIVATION
            }
            SecretMaterialOperation::KeyWrap => Self::SECRET_MATERIAL_OPERATION_KEY_WRAP,
            SecretMaterialOperation::KeyUnwrap => Self::SECRET_MATERIAL_OPERATION_KEY_UNWRAP,
            SecretMaterialOperation::SignatureKeyGeneration => {
                Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_GENERATION
            }
            SecretMaterialOperation::SignatureKeyDerivation => {
                Self::SECRET_MATERIAL_OPERATION_SIGNATURE_KEY_DERIVATION
            }
            SecretMaterialOperation::SignatureSign => {
                Self::SECRET_MATERIAL_OPERATION_SIGNATURE_SIGN
            }
            SecretMaterialOperation::SignatureVerify => {
                Self::SECRET_MATERIAL_OPERATION_SIGNATURE_VERIFY
            }
            SecretMaterialOperation::SignatureEncoding => {
                Self::SECRET_MATERIAL_OPERATION_SIGNATURE_ENCODING
            }
            SecretMaterialOperation::KeyAgreementKeyGeneration => {
                Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_GENERATION
            }
            SecretMaterialOperation::KeyAgreementKeyDerivation => {
                Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_KEY_DERIVATION
            }
            SecretMaterialOperation::KeyAgreementSharedSecret => {
                Self::SECRET_MATERIAL_OPERATION_KEY_AGREEMENT_SHARED_SECRET
            }
            SecretMaterialOperation::KemKeyGeneration => {
                Self::SECRET_MATERIAL_OPERATION_KEM_KEY_GENERATION
            }
            SecretMaterialOperation::KemKeyDerivation => {
                Self::SECRET_MATERIAL_OPERATION_KEM_KEY_DERIVATION
            }
            SecretMaterialOperation::KemEncapsulate => {
                Self::SECRET_MATERIAL_OPERATION_KEM_ENCAPSULATE
            }
            SecretMaterialOperation::KemDecapsulate => {
                Self::SECRET_MATERIAL_OPERATION_KEM_DECAPSULATE
            }
            SecretMaterialOperation::HpkeKeyGeneration => {
                Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_GENERATION
            }
            SecretMaterialOperation::HpkeKeyDerivation => {
                Self::SECRET_MATERIAL_OPERATION_HPKE_KEY_DERIVATION
            }
            SecretMaterialOperation::HpkeSenderSetup => {
                Self::SECRET_MATERIAL_OPERATION_HPKE_SENDER_SETUP
            }
            SecretMaterialOperation::HpkeReceiverSetup => {
                Self::SECRET_MATERIAL_OPERATION_HPKE_RECEIVER_SETUP
            }
            SecretMaterialOperation::HpkeSeal => Self::SECRET_MATERIAL_OPERATION_HPKE_SEAL,
            SecretMaterialOperation::HpkeOpen => Self::SECRET_MATERIAL_OPERATION_HPKE_OPEN,
            SecretMaterialOperation::HpkeExport => Self::SECRET_MATERIAL_OPERATION_HPKE_EXPORT,
            SecretMaterialOperation::RandomFill => Self::SECRET_MATERIAL_OPERATION_RANDOM_FILL,
            SecretMaterialOperation::RandomNonce => Self::SECRET_MATERIAL_OPERATION_RANDOM_NONCE,
            SecretMaterialOperation::RandomSalt => Self::SECRET_MATERIAL_OPERATION_RANDOM_SALT,
            SecretMaterialOperation::PublicKeyEncoding => {
                Self::SECRET_MATERIAL_OPERATION_PUBLIC_KEY_ENCODING
            }
        }
    }
}

// These conversions report native enforcement decisions. No reverse conversion
// accepts a caller record as ownership, retention or export authorization.
impl From<MaterialPolicy> for ProtoMaterialPolicy {
    fn from(value: MaterialPolicy) -> Self {
        // An added native field must acquire a schema mapping before this compiles.
        let MaterialPolicy {
            owner,
            sensitivity,
            retention,
            zeroization,
            export,
            destruction,
        } = value;
        Self {
            owner: ProtoBufferOwner::from(owner).into(),
            sensitivity: ProtoSecretSensitivity::from(sensitivity).into(),
            retention: ProtoRetentionPolicy::from(retention).into(),
            zeroization: ProtoZeroizationPolicy::from(zeroization).into(),
            export: ProtoExportPolicy::from(export).into(),
            destruction: ProtoDestructionPolicy::from(destruction).into(),
        }
    }
}

impl From<OperationSecretMaterialPolicy> for ProtoOperationSecretMaterialPolicy {
    fn from(value: OperationSecretMaterialPolicy) -> Self {
        // An added native field must acquire a schema mapping before this compiles.
        let OperationSecretMaterialPolicy {
            input,
            output,
            request_wire,
            response_wire,
            output_material,
        } = value;
        Self {
            input: MessageField::some(input.into()),
            output: MessageField::some(output.into()),
            request_wire: MessageField::some(request_wire.into()),
            response_wire: MessageField::some(response_wire.into()),
            output_material: ProtoOutputMaterial::from(output_material).into(),
        }
    }
}
