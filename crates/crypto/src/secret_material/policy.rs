// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::{
    BufferOwner, DestructionPolicy, ExportPolicy, OutputMaterial, RetentionPolicy,
    SecretSensitivity, ZeroizationPolicy,
};
use crypto_core::RngOutputKind;

/// Semantic operation whose entry point binds a secret-material policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretMaterialOperation {
    /// Authenticated encryption.
    AeadSeal,
    /// Authenticated decryption.
    AeadOpen,
    /// Constant-time comparison.
    ConstantTimeCompare,
    /// Cryptographic hashing.
    Hash,
    /// Message authentication tag generation.
    MacAuthenticate,
    /// Message authentication tag verification.
    MacVerify,
    /// Password or key derivation.
    KeyDerivation,
    /// Symmetric key wrapping.
    KeyWrap,
    /// Symmetric key unwrapping.
    KeyUnwrap,
    /// Signature keypair generation.
    SignatureKeyGeneration,
    /// Signature keypair derivation.
    SignatureKeyDerivation,
    /// Signature creation.
    SignatureSign,
    /// Signature verification.
    SignatureVerify,
    /// Key-agreement keypair generation.
    KeyAgreementKeyGeneration,
    /// Key-agreement keypair derivation.
    KeyAgreementKeyDerivation,
    /// Shared-secret derivation.
    KeyAgreementSharedSecret,
    /// KEM keypair generation.
    KemKeyGeneration,
    /// KEM keypair derivation.
    KemKeyDerivation,
    /// KEM encapsulation.
    KemEncapsulate,
    /// KEM decapsulation.
    KemDecapsulate,
    /// HPKE keypair generation.
    HpkeKeyGeneration,
    /// HPKE keypair derivation.
    HpkeKeyDerivation,
    /// Establishment of a live, non-exportable HPKE sender context.
    HpkeSenderSetup,
    /// Establishment of a live, non-exportable HPKE receiver context.
    HpkeReceiverSetup,
    /// HPKE sealing.
    HpkeSeal,
    /// HPKE opening.
    HpkeOpen,
    /// HPKE exporter-secret derivation.
    HpkeExport,
    /// Fill caller-owned storage with cryptographically secure random bytes.
    RandomFill,
    /// Generate an AEAD nonce.
    RandomNonce,
    /// Generate an Argon2 salt.
    RandomSalt,
    /// Public-key encoding or decoding.
    PublicKeyEncoding,
}

/// Ownership, retention, export, and destruction rules for one buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MaterialPolicy {
    /// Layer responsible for the buffer.
    pub owner: BufferOwner,
    /// Sensitivity of its contents.
    pub sensitivity: SecretSensitivity,
    /// Maximum intended lifetime.
    pub retention: RetentionPolicy,
    /// Required zeroization behavior.
    pub zeroization: ZeroizationPolicy,
    /// Whether and how it may cross the boundary.
    pub export: ExportPolicy,
    /// Required destruction behavior.
    pub destruction: DestructionPolicy,
}

/// Complete policy bound to a semantic operation entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OperationSecretMaterialPolicy {
    /// Caller-supplied or decoded operation input.
    pub input: MaterialPolicy,
    /// Semantic operation result before adapter encoding.
    pub output: MaterialPolicy,
    /// Encoded operation request bytes.
    pub request_wire: MaterialPolicy,
    /// Encoded operation response bytes.
    pub response_wire: MaterialPolicy,
    /// Security-relevant class of the semantic result.
    pub output_material: OutputMaterial,
}

/// Return the reviewed material policy for one semantic operation.
#[must_use]
pub const fn operation_secret_material_policy(
    operation: SecretMaterialOperation,
) -> OperationSecretMaterialPolicy {
    match operation {
        SecretMaterialOperation::AeadSeal | SecretMaterialOperation::KeyWrap => {
            secret_input_sensitive_output(OutputMaterial::SensitivePublic)
        }
        SecretMaterialOperation::AeadOpen
        | SecretMaterialOperation::KeyUnwrap
        | SecretMaterialOperation::KeyDerivation
        | SecretMaterialOperation::KeyAgreementSharedSecret
        | SecretMaterialOperation::KemDecapsulate
        | SecretMaterialOperation::HpkeOpen
        | SecretMaterialOperation::HpkeExport => secret_output(OutputMaterial::Secret),
        SecretMaterialOperation::RandomFill => caller_owned_secret_output(),
        SecretMaterialOperation::RandomNonce => public_operation(),
        SecretMaterialOperation::RandomSalt => {
            public_input_sensitive_output(OutputMaterial::SensitivePublic)
        }
        SecretMaterialOperation::SignatureKeyGeneration
        | SecretMaterialOperation::KeyAgreementKeyGeneration
        | SecretMaterialOperation::KemKeyGeneration
        | SecretMaterialOperation::KemEncapsulate
        | SecretMaterialOperation::HpkeKeyGeneration => {
            public_input_secret_output(OutputMaterial::Mixed)
        }
        SecretMaterialOperation::SignatureKeyDerivation
        | SecretMaterialOperation::KeyAgreementKeyDerivation
        | SecretMaterialOperation::KemKeyDerivation
        | SecretMaterialOperation::HpkeKeyDerivation => secret_output(OutputMaterial::Mixed),
        SecretMaterialOperation::HpkeSenderSetup | SecretMaterialOperation::HpkeReceiverSetup => {
            secret_input_non_exportable_output(OutputMaterial::Mixed)
        }
        SecretMaterialOperation::HpkeSeal => {
            secret_input_sensitive_output(OutputMaterial::SensitivePublic)
        }
        SecretMaterialOperation::Hash
        | SecretMaterialOperation::ConstantTimeCompare
        | SecretMaterialOperation::MacAuthenticate
        | SecretMaterialOperation::MacVerify
        | SecretMaterialOperation::SignatureSign => {
            secret_input_public_output(OutputMaterial::Public)
        }
        SecretMaterialOperation::SignatureVerify | SecretMaterialOperation::PublicKeyEncoding => {
            public_operation()
        }
    }
}

/// Return the reviewed caller-owned output policy for one random purpose.
#[must_use]
pub const fn random_fill_secret_material_policy(
    kind: RngOutputKind,
) -> OperationSecretMaterialPolicy {
    match kind {
        RngOutputKind::AeadNonce12 => caller_owned_public_output(),
        RngOutputKind::Argon2Salt16 | RngOutputKind::Argon2Salt32 => {
            caller_owned_sensitive_output()
        }
        RngOutputKind::Generic
        | RngOutputKind::Aes256GcmKey
        | RngOutputKind::MlKem1024Seed
        | RngOutputKind::MlDsa87Seed
        | RngOutputKind::Ed25519Seed
        | RngOutputKind::SlhDsaSha2_128sSeed => caller_owned_secret_output(),
        _ => caller_owned_secret_output(),
    }
}

/// Bind a reviewed policy in production code without retaining runtime data.
///
/// Keeping this call in every semantic entry point makes policy omissions
/// mechanically searchable and prevents tests from being the only evidence.
#[inline]
pub(crate) const fn bind_operation_policy(
    operation: SecretMaterialOperation,
) -> OperationSecretMaterialPolicy {
    operation_secret_material_policy(operation)
}

#[inline]
#[cfg(feature = "csprng")]
pub(crate) const fn bind_random_fill_policy(kind: RngOutputKind) -> OperationSecretMaterialPolicy {
    random_fill_secret_material_policy(kind)
}

const fn secret_input_public_output(
    output_material: OutputMaterial,
) -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_secret(),
        public_result(),
        secret_wire(),
        public_wire(),
        output_material,
    )
}

const fn secret_input_sensitive_output(
    output_material: OutputMaterial,
) -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_secret(),
        sensitive_result(),
        secret_wire(),
        sensitive_wire(),
        output_material,
    )
}

const fn secret_output(output_material: OutputMaterial) -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_secret(),
        owned_secret(),
        secret_wire(),
        secret_wire(),
        output_material,
    )
}

const fn secret_input_non_exportable_output(
    output_material: OutputMaterial,
) -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_secret(),
        MaterialPolicy {
            owner: BufferOwner::OperationLayer,
            sensitivity: SecretSensitivity::Secret,
            retention: RetentionPolicy::ResultLifetime,
            zeroization: ZeroizationPolicy::OwnerZeroizesOnDrop,
            export: ExportPolicy::NonExportable,
            destruction: DestructionPolicy::ZeroizeOnDrop,
        },
        public_wire(),
        public_wire(),
        output_material,
    )
}

const fn public_input_secret_output(
    output_material: OutputMaterial,
) -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_public(),
        owned_secret(),
        public_wire(),
        secret_wire(),
        output_material,
    )
}

const fn public_input_sensitive_output(
    output_material: OutputMaterial,
) -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_public(),
        sensitive_result(),
        public_wire(),
        sensitive_wire(),
        output_material,
    )
}

const fn caller_owned_secret_output() -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_public(),
        MaterialPolicy {
            owner: BufferOwner::Caller,
            sensitivity: SecretSensitivity::Secret,
            retention: RetentionPolicy::ResultLifetime,
            zeroization: ZeroizationPolicy::CallerRetainsResponsibility,
            export: ExportPolicy::SecretOwnerRequired,
            destruction: DestructionPolicy::CallerControlled,
        },
        public_wire(),
        secret_wire(),
        OutputMaterial::Secret,
    )
}

const fn caller_owned_sensitive_output() -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_public(),
        MaterialPolicy {
            owner: BufferOwner::Caller,
            sensitivity: SecretSensitivity::Sensitive,
            retention: RetentionPolicy::ResultLifetime,
            zeroization: ZeroizationPolicy::OwnerZeroizesOnDrop,
            export: ExportPolicy::Public,
            destruction: DestructionPolicy::ZeroizeOnDrop,
        },
        public_wire(),
        sensitive_wire(),
        OutputMaterial::SensitivePublic,
    )
}

const fn caller_owned_public_output() -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_public(),
        MaterialPolicy {
            owner: BufferOwner::Caller,
            sensitivity: SecretSensitivity::Public,
            retention: RetentionPolicy::ResultLifetime,
            zeroization: ZeroizationPolicy::NotRequired,
            export: ExportPolicy::Public,
            destruction: DestructionPolicy::NoneRequired,
        },
        public_wire(),
        public_wire(),
        OutputMaterial::Public,
    )
}

const fn public_operation() -> OperationSecretMaterialPolicy {
    operation_policy(
        borrowed_public(),
        public_result(),
        public_wire(),
        public_wire(),
        OutputMaterial::Public,
    )
}

const fn operation_policy(
    input: MaterialPolicy,
    output: MaterialPolicy,
    request_wire: MaterialPolicy,
    response_wire: MaterialPolicy,
    output_material: OutputMaterial,
) -> OperationSecretMaterialPolicy {
    OperationSecretMaterialPolicy {
        input,
        output,
        request_wire,
        response_wire,
        output_material,
    }
}

const fn borrowed_secret() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::Caller,
        sensitivity: SecretSensitivity::Secret,
        retention: RetentionPolicy::BorrowedForCall,
        zeroization: ZeroizationPolicy::CallerRetainsResponsibility,
        export: ExportPolicy::SecretOwnerRequired,
        destruction: DestructionPolicy::CallerControlled,
    }
}

const fn borrowed_public() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::Caller,
        sensitivity: SecretSensitivity::Public,
        retention: RetentionPolicy::BorrowedForCall,
        zeroization: ZeroizationPolicy::NotRequired,
        export: ExportPolicy::Public,
        destruction: DestructionPolicy::NoneRequired,
    }
}

const fn owned_secret() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::OperationLayer,
        sensitivity: SecretSensitivity::Secret,
        retention: RetentionPolicy::ResultLifetime,
        zeroization: ZeroizationPolicy::OwnerZeroizesOnDrop,
        export: ExportPolicy::SecretOwnerRequired,
        destruction: DestructionPolicy::ZeroizeOnDrop,
    }
}

const fn public_result() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::OperationLayer,
        sensitivity: SecretSensitivity::Public,
        retention: RetentionPolicy::ResultLifetime,
        zeroization: ZeroizationPolicy::NotRequired,
        export: ExportPolicy::Public,
        destruction: DestructionPolicy::NoneRequired,
    }
}

const fn sensitive_result() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::OperationLayer,
        sensitivity: SecretSensitivity::Sensitive,
        retention: RetentionPolicy::ResultLifetime,
        zeroization: ZeroizationPolicy::NotRequired,
        export: ExportPolicy::Public,
        destruction: DestructionPolicy::NoneRequired,
    }
}

const fn secret_wire() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::OperationContract,
        sensitivity: SecretSensitivity::Secret,
        retention: RetentionPolicy::OperationTemporary,
        zeroization: ZeroizationPolicy::OwnerZeroizesOnDrop,
        export: ExportPolicy::SecretOwnerRequired,
        destruction: DestructionPolicy::ZeroizeOnDrop,
    }
}

const fn public_wire() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::OperationContract,
        sensitivity: SecretSensitivity::Public,
        retention: RetentionPolicy::OperationTemporary,
        zeroization: ZeroizationPolicy::NotRequired,
        export: ExportPolicy::Public,
        destruction: DestructionPolicy::NoneRequired,
    }
}

const fn sensitive_wire() -> MaterialPolicy {
    MaterialPolicy {
        owner: BufferOwner::OperationContract,
        sensitivity: SecretSensitivity::Sensitive,
        retention: RetentionPolicy::OperationTemporary,
        zeroization: ZeroizationPolicy::NotRequired,
        export: ExportPolicy::Public,
        destruction: DestructionPolicy::NoneRequired,
    }
}
