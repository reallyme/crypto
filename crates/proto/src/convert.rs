// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical failure for an unsupported generated identity.

/// Schema-defined unsupported-identity error shared by all native bridges.
pub const UNSUPPORTED_IDENTITY: crate::error_types::CryptoError =
    crate::error_types::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM;
/// Identity conversion failure, with the canonical schema reason.
pub type UnsupportedProtoAlgorithm = crate::error_types::CryptoError;

/// Canonical value returned for every unsupported identity.
#[allow(non_upper_case_globals)]
pub const UnsupportedProtoAlgorithm: UnsupportedProtoAlgorithm = UNSUPPORTED_IDENTITY;
