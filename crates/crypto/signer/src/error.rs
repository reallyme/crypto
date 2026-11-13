// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signer adapters preserve the schema-defined native failure unchanged.

/// Canonical signing failure.
pub use crypto_core::CryptoError as SignerError;
/// Canonical verification failure.
pub use crypto_core::CryptoError as VerifierError;
