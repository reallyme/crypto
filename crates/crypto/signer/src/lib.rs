// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Crypto signer abstraction.
//!
//! Responsible for exposing signer traits and in-process signer adapters.
//! Not responsible for defining algorithm primitives or custody policy.
//! Assumes callers pass already validated key material for the chosen algorithm.
//! Guarantees signer-owned secret bytes are stored in zeroizing secret wrappers.

mod dispatch_signer;
mod dispatch_verifier;
mod error;
mod signer;
mod verifier;

pub use dispatch_signer::DispatchSigner;
pub use dispatch_verifier::DispatchVerifier;
pub use error::{SignerError, SignerFailureKind, VerifierError, VerifierFailureKind};
pub use signer::Signer;
pub use verifier::Verifier;
