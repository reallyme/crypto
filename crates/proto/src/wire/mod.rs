// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Lossless protobuf boundary helpers.
//!
//! Native SDK facades intentionally expose small ergonomic error enums. This
//! module is the lower-level wire contract: it preserves whether a failure is
//! primitive-, provider-, or backend-owned and keeps the exact protobuf reason
//! code intact when serialized error bytes need to pass through a service or
//! FFI-style boundary.

mod codec;
mod error;
mod limits;
mod mapping;

pub(crate) use codec::decode_json;
pub use codec::{decode_protobuf, encode_protobuf};
pub use error::{CryptoWireError, CryptoWireErrorBranch, CryptoWireErrorValidationError};
pub use limits::{
    CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT, MAX_CRYPTO_PROTO_JSON_BYTES,
    MAX_CRYPTO_PROTO_MESSAGE_BYTES,
};
