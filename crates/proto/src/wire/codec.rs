// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::{DecodeOptions, Message};
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::generated::proto::reallyme::crypto::v1::CryptoErrorReason;

use super::error::CryptoWireError;
use super::limits::{
    CRYPTO_PROTO_RECURSION_LIMIT, CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT, MAX_CRYPTO_PROTO_JSON_BYTES,
    MAX_CRYPTO_PROTO_MESSAGE_BYTES,
};

/// Encodes a generated protobuf message into owned zeroizing bytes.
pub fn encode_protobuf<M: Message>(message: &M) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(message.encode_to_vec())
}

/// Decodes a generated protobuf message from binary protobuf bytes.
pub fn decode_protobuf<M: Message>(bytes: &[u8]) -> Result<M, CryptoWireError> {
    decode_protobuf_with_limit(bytes, MAX_CRYPTO_PROTO_MESSAGE_BYTES)
}

pub(super) fn decode_protobuf_with_limit<M: Message>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<M, CryptoWireError> {
    if bytes.len() > max_bytes {
        return Err(CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        ));
    }
    DecodeOptions::new()
        .with_recursion_limit(CRYPTO_PROTO_RECURSION_LIMIT)
        .with_unknown_field_limit(CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT)
        .with_max_message_size(max_bytes)
        .decode_from_slice(bytes)
        .map_err(|_| CryptoWireError::malformed_protobuf())
}

/// Decodes a generated protobuf message from proto3-compatible JSON bytes.
///
/// This helper is crate-private because executable operation JSON must first
/// pass the operation-specific secret policy in `operation_request_wire`.
pub(crate) fn decode_json<M: DeserializeOwned + Message>(
    bytes: &[u8],
) -> Result<M, CryptoWireError> {
    if bytes.len() > MAX_CRYPTO_PROTO_JSON_BYTES {
        return Err(CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        ));
    }

    let message: M = serde_json::from_slice(bytes).map_err(|_| {
        CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
        )
    })?;
    if encode_protobuf(&message).len() > MAX_CRYPTO_PROTO_MESSAGE_BYTES {
        return Err(CryptoWireError::primitive_internal(
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
        ));
    }
    Ok(message)
}
