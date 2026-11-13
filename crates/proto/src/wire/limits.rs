// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(super) const CRYPTO_PROTO_RECURSION_LIMIT: u32 =
    crate::contract_constants::proto_wire::CRYPTO_PROTO_RECURSION_LIMIT;
pub(super) const CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT: usize =
    crate::contract_constants::proto_wire::CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT;
pub(super) const PRIMITIVE_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> =
    crate::contract_constants::proto_wire::PRIMITIVE_REASON_CODE_MIN
        ..=crate::contract_constants::proto_wire::PRIMITIVE_REASON_CODE_MAX;
pub(super) const PROVIDER_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> =
    crate::contract_constants::proto_wire::PROVIDER_REASON_CODE_MIN
        ..=crate::contract_constants::proto_wire::PROVIDER_REASON_CODE_MAX;
pub(super) const BACKEND_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> =
    crate::contract_constants::proto_wire::BACKEND_REASON_CODE_MIN
        ..=crate::contract_constants::proto_wire::BACKEND_REASON_CODE_MAX;

/// Maximum accepted protobuf message size at the crypto wire boundary.
pub const MAX_CRYPTO_PROTO_MESSAGE_BYTES: usize =
    crate::contract_constants::proto_wire::MAX_CRYPTO_PROTO_MESSAGE_BYTES;

/// Maximum accepted JSON message size at the crypto wire boundary.
pub const MAX_CRYPTO_PROTO_JSON_BYTES: usize =
    crate::contract_constants::proto_wire::MAX_CRYPTO_PROTO_JSON_BYTES;

/// Maximum encoded size accepted for a standalone serialized `CryptoError`.
pub const CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT: usize =
    crate::contract_constants::proto_wire::CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT;
