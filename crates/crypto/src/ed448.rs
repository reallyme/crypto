// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ordinary RFC 8032 Ed448 with empty context.
//!
//! The portable owner protects seeds, expanded material and signing scalars.
//! The optional native provider selects verification explicitly; it never
//! changes the ownership of software signing keys.

mod key;
mod scalar;
mod transcript;
mod verify;

pub use key::Ed448Key;
use thiserror::Error;
pub use verify::verify;

/// RFC 8032 Ed448 public-key length.
pub const PUBLIC_KEY_LEN: usize = 57;
/// RFC 8032 Ed448 signature length.
pub const SIGNATURE_LEN: usize = 114;
/// RFC 8032 private seed length.
pub const SEED_LEN: usize = 57;

/// Secret-free failures for the ordinary Ed448 contract.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ed448Error {
    /// No reviewed verification provider is selected for this target.
    #[error("unsupported Ed448 algorithm")]
    UnsupportedAlgorithm,
    /// The selected operation has no protected software implementation.
    #[error("unsupported Ed448 operation")]
    UnsupportedOperation,
    /// A seed has an invalid length or its owner has been explicitly cleared.
    #[error("invalid Ed448 private key")]
    InvalidPrivateKey,
    /// Protected key storage could not be allocated.
    #[error("Ed448 allocation failed")]
    AllocationFailed,
    /// The entropy source failed, including a partially filled destination.
    #[error("Ed448 randomness unavailable")]
    RandomnessUnavailable,
    /// The public-key encoding is invalid or a small-order key was supplied.
    #[error("invalid Ed448 public key")]
    InvalidPublicKey,
    /// The signature encoding, point decoding or verification is invalid.
    #[error("invalid Ed448 signature")]
    InvalidSignature,
    /// The opaque signing provider failed.
    #[error("Ed448 provider failed")]
    ProviderFailed,
}

/// Distinct operations so feature presence cannot imply private-key support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ed448Operation {
    /// Ordinary Ed448 signature verification.
    Verify,
    /// Signing by an explicitly injected non-exporting key provider.
    OpaqueSign,
    /// Protected software private-key generation.
    SoftwareKeyGeneration,
    /// Protected software private-key import.
    SoftwareKeyImport,
}

/// Check an operation before advertising it to a caller.
pub fn require_support(operation: Ed448Operation) -> Result<(), Ed448Error> {
    match operation {
        Ed448Operation::SoftwareKeyGeneration | Ed448Operation::SoftwareKeyImport => Ok(()),
        Ed448Operation::Verify | Ed448Operation::OpaqueSign => {
            #[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
            if !crate::native_provider::is_available() {
                return Err(Ed448Error::UnsupportedAlgorithm);
            }
            Ok(())
        }
    }
}

/// Non-exporting signing boundary. The provider owns key generation, private
/// storage and its cleanup; no private bytes cross this interface.
pub trait OpaqueEd448Signer {
    /// Public key associated with the opaque private key.
    fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN];
    /// Sign exact message bytes using ordinary Ed448 with empty context.
    fn sign_message(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Ed448Error>;
}

/// Obtain an opaque signature and verify its key association and exact message
/// before returning it. Unsupported targets fail before calling the provider.
pub fn sign_with_provider(
    provider: &impl OpaqueEd448Signer,
    message: &[u8],
) -> Result<[u8; SIGNATURE_LEN], Ed448Error> {
    require_support(Ed448Operation::OpaqueSign)?;
    let public = provider.public_key();
    let signature = provider.sign_message(message)?;
    verify(public, message, &signature)?;
    Ok(signature)
}
