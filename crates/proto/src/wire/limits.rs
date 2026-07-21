// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

pub(super) const CRYPTO_PROTO_RECURSION_LIMIT: u32 = 64;
pub(super) const CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;
pub(super) const PRIMITIVE_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> = 100..=199;
pub(super) const PROVIDER_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> = 200..=299;
pub(super) const BACKEND_REASON_CODE_RANGE: core::ops::RangeInclusive<i32> = 300..=399;

/// Maximum accepted protobuf message size at the crypto wire boundary.
pub const MAX_CRYPTO_PROTO_MESSAGE_BYTES: usize = 1024 * 1024;

/// Maximum accepted JSON message size at the crypto wire boundary.
pub const MAX_CRYPTO_PROTO_JSON_BYTES: usize = 1_572_864;

/// Maximum encoded size accepted for a standalone serialized `CryptoError`.
pub const CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT: usize = 1024;
