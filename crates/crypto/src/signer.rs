// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Keep the umbrella's reviewed 0.3.9 signer surface explicit. Re-exporting
// the entire crate changes the public module shape and can expose new internals.
pub use crypto_signer::{
    DispatchSigner, DispatchVerifier, Signer, SignerError, SignerFailureKind, Verifier,
    VerifierError, VerifierFailureKind,
};
