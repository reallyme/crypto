// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operations preserve the schema-defined native failure unchanged.

/// Canonical schema-defined operation failure.
pub use crypto_core::CryptoError as OperationError;
