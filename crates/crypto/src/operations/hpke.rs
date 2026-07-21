// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for HPKE key management, encryption, and export operations.

use crypto_hpke::{
    HpkeError, HpkeExporterSecret, HpkeKeyPair, HpkeOpenOutput, HpkeOpenRequest,
    HpkePskOpenRequest, HpkePskSealRequest, HpkeReceiverExportRequest, HpkeSealOutput,
    HpkeSealRequest, HpkeSenderExportOutput, HpkeSenderExportRequest, HpkeSuite,
};

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Generates a recipient keypair for the selected HPKE KEM.
pub fn keygen(suite: HpkeSuite) -> Result<HpkeKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeKeyGeneration);
    crypto_hpke::keygen(suite).map_err(map_hpke_error)
}

/// Deterministically derives a recipient keypair from suite-specific input keying material.
pub fn derive_keypair(
    suite: HpkeSuite,
    input_key_material: &[u8],
) -> Result<HpkeKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeKeyDerivation);
    crypto_hpke::derive_keypair(suite, input_key_material).map_err(map_hpke_error)
}

/// Seals one HPKE Base-mode message.
///
/// The caller does not supply a nonce. HPKE derives the AEAD nonce from the
/// key schedule and fresh KEM encapsulation state inside the protocol owner.
pub fn seal_base(request: &HpkeSealRequest<'_>) -> Result<HpkeSealOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeSeal);
    crypto_hpke::seal_base(request).map_err(map_hpke_error)
}

/// Opens and authenticates one HPKE Base-mode message.
pub fn open_base(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeOpen);
    crypto_hpke::open_base(request).map_err(map_hpke_error)
}

/// Establishes an HPKE sender context and exports secret keying material.
pub fn sender_export(
    request: &HpkeSenderExportRequest<'_>,
) -> Result<HpkeSenderExportOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeExport);
    crypto_hpke::sender_export(request).map_err(map_hpke_error)
}

/// Establishes the matching HPKE receiver context and exports secret keying material.
pub fn receiver_export(
    request: &HpkeReceiverExportRequest<'_>,
) -> Result<HpkeExporterSecret, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeExport);
    crypto_hpke::receiver_export(request).map_err(map_hpke_error)
}

/// Seals one HPKE PSK-mode message with paired high-entropy PSK inputs.
pub fn seal_psk(request: &HpkePskSealRequest<'_>) -> Result<HpkeSealOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeSeal);
    crypto_hpke::seal_psk(request).map_err(map_hpke_error)
}

/// Opens and authenticates one HPKE PSK-mode message.
pub fn open_psk(request: &HpkePskOpenRequest<'_>) -> Result<HpkeOpenOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeOpen);
    crypto_hpke::open_psk(request).map_err(map_hpke_error)
}

fn map_hpke_error(error: HpkeError) -> OperationError {
    match error {
        HpkeError::UnsupportedKem
        | HpkeError::UnsupportedKdf
        | HpkeError::UnsupportedAead
        | HpkeError::UnsupportedSuite => OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        },
        HpkeError::InvalidPublicKey => primitive(PrimitiveErrorReason::InvalidPublicKey),
        HpkeError::InvalidPrivateKey => primitive(PrimitiveErrorReason::InvalidPrivateKey),
        HpkeError::InvalidEncapsulatedKey | HpkeError::InvalidCiphertext => {
            primitive(PrimitiveErrorReason::MalformedCiphertext)
        }
        HpkeError::InvalidInputKeyMaterial
        | HpkeError::InvalidInfoLength
        | HpkeError::InvalidExporterLength => primitive(PrimitiveErrorReason::InvalidLength),
        HpkeError::LengthOverflow => primitive(PrimitiveErrorReason::LengthOverflow),
        HpkeError::InvalidPsk | HpkeError::InvalidPskIdentifier | HpkeError::InvalidRandomness => {
            primitive(PrimitiveErrorReason::InvalidParameter)
        }
        HpkeError::OpenFailed => primitive(PrimitiveErrorReason::VerificationFailed),
        HpkeError::RandomnessUnavailable => OperationError::Provider {
            reason: ProviderErrorReason::RandomnessUnavailable,
        },
        HpkeError::SealFailed | HpkeError::ExportFailed | HpkeError::KeyGenerationFailed => {
            OperationError::Backend {
                reason: BackendErrorReason::Internal,
            }
        }
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}

fn primitive(reason: PrimitiveErrorReason) -> OperationError {
    OperationError::Primitive { reason }
}
