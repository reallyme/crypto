// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ReallyMe crypto protobuf identifiers with generated Buffa bindings.

/// Schema-generated reasons and validated native errors without message codecs.
#[cfg(feature = "error-types")]
#[path = "generated/error_contract.rs"]
pub mod error_types;

/// Generated protobuf boundary.
pub mod generated;

#[cfg(feature = "generated")]
mod merge_sensitive;

/// Canonical typed failure for generated identity conversions.
#[cfg(feature = "generated")]
pub mod convert;

/// Lossless protobuf error and result helpers for service, FFI, WASM, JNI,
/// and SDK adapter boundaries.
#[cfg(feature = "generated")]
pub mod wire;

/// Strict codecs for the generated operation response boundary.
#[cfg(feature = "generated")]
pub mod operation_response_wire;

/// Strict codecs for the generated operation request boundary.
#[cfg(feature = "generated")]
pub mod operation_request_wire;
