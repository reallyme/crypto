// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Public operation-contract entrypoints for encoded `CryptoOperationRequest`
//! values.

use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoOperationResponse;
use crypto_proto::operation_request_wire::{
    decode_operation_request, decode_operation_request_json,
};
use crypto_proto::operation_response_wire::encode_operation_response_or_error;
use zeroize::Zeroizing;

use super::error::error_response;
use super::request::process_operation_request;

/// Execute a binary generated-protobuf crypto operation request and return the
/// generated operation response contract.
#[must_use]
pub fn process_operation_response(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    encode_operation_response_or_error(&process_operation_response_output(request_bytes))
}

/// Execute a binary generated-protobuf request and retain the generated message.
#[must_use]
pub fn process_operation_response_output(request_bytes: &[u8]) -> CryptoOperationResponse {
    match decode_operation_request(request_bytes) {
        Ok(request) => process_operation_request(request),
        Err(error) => error_response(error),
    }
}

/// Execute a permitted non-secret generated ProtoJSON crypto request and return
/// one binary generated operation response.
#[must_use]
pub fn process_operation_response_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    encode_operation_response_or_error(&process_operation_response_json_output(request_json))
}

/// Execute a permitted non-secret generated ProtoJSON request and retain the
/// generated message. Secret-bearing selectors fail before value decoding.
#[must_use]
pub fn process_operation_response_json_output(request_json: &[u8]) -> CryptoOperationResponse {
    match decode_operation_request_json(request_json) {
        Ok(request) => process_operation_request(request),
        Err(error) => error_response(error),
    }
}
