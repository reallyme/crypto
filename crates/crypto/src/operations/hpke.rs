// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for HPKE key management, encryption, and export operations.

use crypto_hpke::{
    HpkeError, HpkeExporterSecret, HpkeKeyPair, HpkeOpenOutput, HpkeOpenRequest,
    HpkePskOpenRequest, HpkePskSealRequest, HpkeReceiverExportRequest, HpkeSealOutput,
    HpkeSealRequest, HpkeSenderExportOutput, HpkeSenderExportRequest, HpkeSuite,
};
use zeroize::ZeroizeOnDrop;

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Minimum IKM length accepted by operation and serialized HPKE boundaries.
///
/// The raw HPKE primitive retains the KEM-defined non-empty input contract for
/// conformance and protocol-specific use. Public operation transports apply a
/// 256-bit floor so accidental low-entropy caller input fails closed.
pub const HPKE_OPERATION_MIN_INPUT_KEY_MATERIAL_LEN: usize = 32;

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

/// Deterministically derives a recipient keypair from arbitrary-length input keying material.
///
/// The selected KEM owns its registered HPKE `DeriveKeyPair` procedure, so MLS
/// adapters do not need to reproduce KEM-specific normalization themselves.
pub fn derive_keypair_from_ikm(
    suite: HpkeSuite,
    input_key_material: &[u8],
) -> Result<HpkeKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeKeyDerivation);
    if input_key_material.len() < HPKE_OPERATION_MIN_INPUT_KEY_MATERIAL_LEN {
        return Err(primitive(PrimitiveErrorReason::InvalidLength));
    }
    crypto_hpke::derive_keypair_from_ikm(suite, input_key_material).map_err(map_hpke_error)
}

/// Result of establishing a live HPKE PSK-mode sender context.
pub struct HpkePskSenderSetupOutput {
    /// Encapsulated key that the caller can bind into message AAD.
    pub encapsulated_key: Vec<u8>,
    /// Non-exportable sender context containing the HPKE traffic state.
    pub context: HpkeSenderContext,
}

/// Operation-layer owner for a live HPKE sender context.
pub struct HpkeSenderContext {
    inner: crypto_hpke::HpkeSenderContext,
}

// The primitive context implements the same destruction contract and owns all
// secret state. This wrapper adds operation-error mapping without weakening it.
impl ZeroizeOnDrop for HpkeSenderContext {}

impl HpkeSenderContext {
    /// Encrypts one message and advances the context sequence number.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OperationError> {
        let _policy = bind_operation_policy(SecretMaterialOperation::HpkeSeal);
        self.inner.seal(aad, plaintext).map_err(map_hpke_error)
    }
}

/// Compatibility name for the PSK-mode sender context.
pub type HpkePskSenderContext = HpkeSenderContext;

/// Operation-layer owner for a live HPKE receiver context.
pub struct HpkeReceiverContext {
    inner: crypto_hpke::HpkeReceiverContext,
}

// The primitive context owns and zeroizes all traffic state. This wrapper only
// adds operation policy binding and deterministic error mapping.
impl ZeroizeOnDrop for HpkeReceiverContext {}

impl HpkeReceiverContext {
    /// Authenticates and decrypts one message and advances the sequence number.
    pub fn open(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<HpkeOpenOutput, OperationError> {
        let _policy = bind_operation_policy(SecretMaterialOperation::HpkeOpen);
        self.inner.open(aad, ciphertext).map_err(map_hpke_error)
    }
}

/// Establishes a PSK-mode sender context before the caller constructs AAD.
pub fn setup_sender_psk(
    request: &crypto_hpke::HpkePskSenderSetupRequest<'_>,
) -> Result<HpkePskSenderSetupOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeSenderSetup);
    let output = crypto_hpke::setup_sender_psk(request).map_err(map_hpke_error)?;
    Ok(HpkePskSenderSetupOutput {
        encapsulated_key: output.encapsulated_key,
        context: HpkeSenderContext {
            inner: output.context,
        },
    })
}

/// Establishes a PSK-mode receiver context for an encapsulated key.
pub fn setup_receiver_psk(
    request: &crypto_hpke::HpkePskReceiverSetupRequest<'_>,
) -> Result<HpkeReceiverContext, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeReceiverSetup);
    let inner = crypto_hpke::setup_receiver_psk(request).map_err(map_hpke_error)?;
    Ok(HpkeReceiverContext { inner })
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

/// Seals one Base-mode message with deterministic KEM randomness.
#[cfg(feature = "test-vectors")]
pub fn seal_base_derand(
    request: &crypto_hpke::HpkeDerandSealRequest<'_>,
) -> Result<HpkeSealOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeSeal);
    crypto_hpke::seal_base_derand(request).map_err(map_hpke_error)
}

/// Establishes a deterministic Base-mode sender context and exports secret material.
#[cfg(feature = "test-vectors")]
pub fn sender_export_derand(
    request: &crypto_hpke::HpkeDerandSenderExportRequest<'_>,
) -> Result<HpkeSenderExportOutput, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::HpkeExport);
    crypto_hpke::sender_export_derand(request).map_err(map_hpke_error)
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
