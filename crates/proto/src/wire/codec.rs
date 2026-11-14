// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use serde::de::DeserializeOwned;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::generated::proto::reallyme::crypto::v1::CryptoErrorReason;

use super::error::CryptoWireError;
use super::limits::{
    CRYPTO_PROTO_RECURSION_LIMIT, CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT, MAX_CRYPTO_PROTO_JSON_BYTES,
    MAX_CRYPTO_PROTO_MESSAGE_BYTES,
};

/// Encodes a generated message directly into bounded clearing storage.
pub fn encode_protobuf<M: Message>(message: &M) -> Result<Zeroizing<Vec<u8>>, CryptoWireError> {
    encode_protobuf_with_limit(message, MAX_CRYPTO_PROTO_MESSAGE_BYTES)
}

pub(crate) fn encode_protobuf_with_limit<M: Message>(
    message: &M,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoWireError> {
    let length = encoded_length(message)?;
    if length > limit {
        return Err(resource_limit());
    }
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(length)
        .map_err(|_| resource_limit())?;
    message
        .try_encode(&mut *encoded)
        .map_err(|_| resource_limit())?;
    Ok(encoded)
}

fn encoded_length<M: Message>(message: &M) -> Result<usize, CryptoWireError> {
    let length = message.try_encoded_len().map_err(|_| resource_limit())?;
    usize::try_from(length).map_err(|_| resource_limit())
}

fn resource_limit() -> CryptoWireError {
    CryptoWireError::primitive_internal(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
    )
}

/// Admits an untrusted protobuf message under the crypto wire budgets.
///
/// Use this before passing wire input to a typed operation adapter. The
/// generated types intentionally cannot retain unknown fields for later checks.
pub fn decode_protobuf<M: Message>(bytes: &[u8]) -> Result<M, CryptoWireError> {
    decode_protobuf_with_limit(bytes, MAX_CRYPTO_PROTO_MESSAGE_BYTES)
}

pub(super) fn decode_protobuf_with_limit<M: Message>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<M, CryptoWireError> {
    check_size(bytes, max_bytes)?;
    strict_options(max_bytes)
        .decode_from_slice(bytes)
        .map_err(|_| CryptoWireError::malformed_protobuf())
}

/// Merges bounded, known-field wire data into a clearing protobuf owner.
///
/// A malformed replacement clears the whole destination. A caller must not
/// keep using the old secret or a partially populated request after failure.
pub fn merge_protobuf<M: Message + ZeroizeOnDrop>(
    message: &mut M,
    bytes: &[u8],
) -> Result<(), CryptoWireError> {
    let result = check_size(bytes, MAX_CRYPTO_PROTO_MESSAGE_BYTES).and_then(|()| {
        strict_options(MAX_CRYPTO_PROTO_MESSAGE_BYTES)
            .merge_from_slice(message, bytes)
            .map_err(|_| CryptoWireError::malformed_protobuf())
    });
    if result.is_err() {
        message.clear();
    }
    result
}

fn strict_options(max_bytes: usize) -> DecodeOptions {
    DecodeOptions::new()
        .with_recursion_limit(CRYPTO_PROTO_RECURSION_LIMIT)
        .with_unknown_field_limit(CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT)
        .reject_unknown_fields()
        .with_max_message_size(max_bytes)
}

fn check_size(bytes: &[u8], max_bytes: usize) -> Result<(), CryptoWireError> {
    if bytes.len() > max_bytes {
        return Err(resource_limit());
    }
    Ok(())
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
    if encoded_length(&message)? > MAX_CRYPTO_PROTO_MESSAGE_BYTES {
        return Err(resource_limit());
    }
    Ok(message)
}
