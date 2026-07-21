// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HPKE protobuf operation adapters.

use crate::hpke::{
    HpkeOpenRequest, HpkePskOpenRequest, HpkePskSealRequest, HpkeReceiverExportRequest,
    HpkeSealRequest, HpkeSenderExportRequest,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoErrorReason, CryptoHpkeDeriveKeyPairRequest, CryptoHpkeGenerateKeyPairRequest,
    CryptoHpkeOpenRequest, CryptoHpkeOpenResult, CryptoHpkePskOpenRequest,
    CryptoHpkePskSealRequest, CryptoHpkeReceiverExportRequest, CryptoHpkeReceiverExportResult,
    CryptoHpkeSealRequest, CryptoHpkeSealedMessage, CryptoHpkeSenderExportRequest,
    CryptoHpkeSenderExportResult, CryptoKeyPair,
};
use crypto_proto::wire::{CryptoWireError, CryptoWireErrorBranch};

use super::algorithms::hpke_suite;
use super::operation_error::map_operation_error;
use super::wire_error::wire_error;

pub(super) fn process_hpke_seal(
    request: CryptoHpkeSealRequest,
) -> Result<CryptoHpkeSealedMessage, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let output = crate::operations::hpke::seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &request.recipient_public_key,
        info: &request.info,
        aad: &request.aad,
        plaintext: &request.plaintext,
    })
    .map_err(map_operation_error)?;
    let result = CryptoHpkeSealedMessage {
        algorithm: request.algorithm.clone(),
        encapsulated_key: output.encapsulated_key,
        ciphertext: output.ciphertext,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_hpke_open(
    request: CryptoHpkeOpenRequest,
) -> Result<CryptoHpkeOpenResult, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let mut output = crate::operations::hpke::open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &request.encapsulated_key,
        recipient_private_key: &request.recipient_secret_key,
        info: &request.info,
        aad: &request.aad,
        ciphertext: &request.ciphertext,
    })
    .map_err(map_operation_error)?;
    let result = CryptoHpkeOpenResult {
        algorithm: request.algorithm.clone(),
        plaintext: core::mem::take(&mut *output.plaintext),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_hpke_generate_key_pair(
    request: CryptoHpkeGenerateKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let key_pair = crate::operations::hpke::keygen(suite).map_err(map_operation_error)?;
    let secret_key = key_pair.private_key().to_vec();
    let result = CryptoKeyPair {
        algorithm: request.algorithm,
        public_key: key_pair.public_key,
        secret_key,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_hpke_derive_key_pair(
    request: CryptoHpkeDeriveKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let key_pair =
        crate::operations::hpke::derive_keypair_from_ikm(suite, &request.input_key_material)
            .map_err(map_operation_error)?;
    let secret_key = key_pair.private_key().to_vec();
    let result = CryptoKeyPair {
        algorithm: request.algorithm.clone(),
        public_key: key_pair.public_key,
        secret_key,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_hpke_sender_export(
    request: CryptoHpkeSenderExportRequest,
) -> Result<CryptoHpkeSenderExportResult, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let output = crate::operations::hpke::sender_export(&HpkeSenderExportRequest {
        suite,
        recipient_public_key: &request.recipient_public_key,
        info: &request.info,
        exporter_context: &request.exporter_context,
        output_length: output_length(request.output_length)?,
    })
    .map_err(map_operation_error)?;
    let exporter_secret = output.exporter_secret().to_vec();
    let result = CryptoHpkeSenderExportResult {
        algorithm: request.algorithm.clone(),
        encapsulated_key: output.encapsulated_key,
        exporter_secret,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_hpke_receiver_export(
    request: CryptoHpkeReceiverExportRequest,
) -> Result<CryptoHpkeReceiverExportResult, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let output = crate::operations::hpke::receiver_export(&HpkeReceiverExportRequest {
        suite,
        encapsulated_key: &request.encapsulated_key,
        recipient_private_key: &request.recipient_secret_key,
        info: &request.info,
        exporter_context: &request.exporter_context,
        output_length: output_length(request.output_length)?,
    })
    .map_err(map_operation_error)?;
    let result = CryptoHpkeReceiverExportResult {
        algorithm: request.algorithm.clone(),
        exporter_secret: output.as_slice().to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_hpke_psk_seal(
    request: CryptoHpkePskSealRequest,
) -> Result<CryptoHpkeSealedMessage, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let output = crate::operations::hpke::seal_psk(&HpkePskSealRequest {
        suite,
        recipient_public_key: &request.recipient_public_key,
        info: &request.info,
        aad: &request.aad,
        plaintext: &request.plaintext,
        psk: &request.psk,
        psk_id: &request.psk_id,
    })
    .map_err(map_operation_error)?;
    let result = CryptoHpkeSealedMessage {
        algorithm: request.algorithm.clone(),
        encapsulated_key: output.encapsulated_key,
        ciphertext: output.ciphertext,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_hpke_psk_open(
    request: CryptoHpkePskOpenRequest,
) -> Result<CryptoHpkeOpenResult, CryptoWireError> {
    let suite = hpke_suite(&request.algorithm)?;
    let mut output = crate::operations::hpke::open_psk(&HpkePskOpenRequest {
        suite,
        encapsulated_key: &request.encapsulated_key,
        recipient_private_key: &request.recipient_secret_key,
        info: &request.info,
        aad: &request.aad,
        ciphertext: &request.ciphertext,
        psk: &request.psk,
        psk_id: &request.psk_id,
    })
    .map_err(map_operation_error)?;
    let result = CryptoHpkeOpenResult {
        algorithm: request.algorithm.clone(),
        plaintext: core::mem::take(&mut *output.plaintext),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

fn output_length(length: u32) -> Result<usize, CryptoWireError> {
    usize::try_from(length).map_err(|_| {
        wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH,
        )
    })
}
