// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ReallyMe crypto protobuf identifiers with generated Buffa bindings.

/// Generated protobuf boundary.
pub mod generated;

/// Conversions between the generated protobuf algorithm identifiers and the
/// internal [`crypto_core`] enums, with a compile-time drift guard.
#[cfg(feature = "generated")]
pub mod convert;

/// Lossless protobuf error and result helpers for service, FFI, WASM, JNI,
/// and SDK adapter boundaries.
#[cfg(feature = "generated")]
pub mod wire;
