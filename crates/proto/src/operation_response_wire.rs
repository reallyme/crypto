// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wire helpers for the generated operation response contract.
//!
//! `CryptoOperationResponse` is the primary 0.3.0 operation boundary.
//! Executable adapters return this contract directly; no opaque alternate
//! result envelope is part of the API.

use buffa::DecodeOptions;

use crate::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    CryptoErrorReason, CryptoOperationResponse,
};
use crate::wire::{encode_protobuf, CryptoWireError, MAX_CRYPTO_PROTO_MESSAGE_BYTES};
use zeroize::Zeroizing;

const CRYPTO_OPERATION_RESPONSE_RECURSION_LIMIT: u32 = 64;
const CRYPTO_OPERATION_RESPONSE_UNKNOWN_FIELD_LIMIT: usize = 0;
const MAX_CRYPTO_OPERATION_RESPONSE_OVERHEAD_BYTES: usize = 32;

/// Maximum accepted encoded size for `CryptoOperationResponse`.
///
/// This mirrors `MAX_CRYPTO_PROTO_MESSAGE_BYTES` plus the fixed wrapper
/// overhead reserved by the operation response contract.
pub const MAX_CRYPTO_OPERATION_RESPONSE_BYTES: usize = match MAX_CRYPTO_PROTO_MESSAGE_BYTES
    .checked_add(MAX_CRYPTO_OPERATION_RESPONSE_OVERHEAD_BYTES)
{
    Some(maximum) => maximum,
    // Both operands are fixed compile-time constants. Capping at the base
    // message limit remains fail-closed if their types ever become smaller.
    None => MAX_CRYPTO_PROTO_MESSAGE_BYTES,
};

/// Encodes a generated operation response under the canonical response-size
/// limit shared by every executable adapter.
pub fn encode_operation_response(
    response: &CryptoOperationResponse,
) -> Result<Zeroizing<Vec<u8>>, CryptoWireError> {
    validate_operation_response(response)?;
    let encoded = encode_protobuf(response);
    if encoded.len() > MAX_CRYPTO_OPERATION_RESPONSE_BYTES {
        return Err(resource_limit_error());
    }
    Ok(encoded)
}

/// Encodes a response and deterministically falls back to a small structured
/// resource-limit response if the original operation result is oversized.
#[must_use]
pub fn encode_operation_response_or_error(
    response: &CryptoOperationResponse,
) -> Zeroizing<Vec<u8>> {
    match encode_operation_response(response) {
        Ok(encoded) => encoded,
        Err(error) => encode_operation_response_unchecked(&error_response(error)),
    }
}

/// Decodes an untrusted binary `CryptoOperationResponse`.
pub fn decode_operation_response(bytes: &[u8]) -> Result<CryptoOperationResponse, CryptoWireError> {
    if bytes.len() > MAX_CRYPTO_OPERATION_RESPONSE_BYTES {
        return Err(resource_limit_error());
    }
    let response = DecodeOptions::new()
        .with_recursion_limit(CRYPTO_OPERATION_RESPONSE_RECURSION_LIMIT)
        .with_unknown_field_limit(CRYPTO_OPERATION_RESPONSE_UNKNOWN_FIELD_LIMIT)
        .with_max_message_size(MAX_CRYPTO_OPERATION_RESPONSE_BYTES)
        .decode_from_slice(bytes)
        .map_err(|_| CryptoWireError::malformed_protobuf())?;
    validate_operation_response(&response)?;
    Ok(response)
}

fn validate_operation_response(response: &CryptoOperationResponse) -> Result<(), CryptoWireError> {
    match response.outcome.as_ref() {
        Some(CryptoOperationOutcome::Result(result)) if result.result.is_some() => Ok(()),
        Some(CryptoOperationOutcome::Error(error)) => CryptoWireError::try_from_proto(error)
            .map(|_| ())
            .map_err(|_| CryptoWireError::malformed_protobuf()),
        Some(CryptoOperationOutcome::Result(_)) | None => {
            Err(CryptoWireError::malformed_protobuf())
        }
    }
}

fn encode_operation_response_unchecked(response: &CryptoOperationResponse) -> Zeroizing<Vec<u8>> {
    encode_protobuf(response)
}

fn error_response(error: CryptoWireError) -> CryptoOperationResponse {
    CryptoOperationResponse {
        outcome: Some(CryptoOperationOutcome::Error(Box::new(error.to_proto()))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn resource_limit_error() -> CryptoWireError {
    CryptoWireError::primitive_internal(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
    )
}
