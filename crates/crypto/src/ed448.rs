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

use crypto_core::CryptoError;
pub use key::Ed448Key;
pub use verify::verify;

/// RFC 8032 Ed448 public-key length.
pub const PUBLIC_KEY_LEN: usize = crypto_core::contract_constants::ed448::PUBLIC_KEY_LEN;
/// RFC 8032 Ed448 signature length.
pub const SIGNATURE_LEN: usize = crypto_core::contract_constants::ed448::SIGNATURE_LEN;
/// RFC 8032 private seed length.
pub const SEED_LEN: usize = crypto_core::contract_constants::ed448::SEED_LEN;

/// Canonical schema-defined error returned by ordinary Ed448 operations.
pub use crypto_core::CryptoError as Ed448Error;

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
pub fn require_support(operation: Ed448Operation) -> Result<(), CryptoError> {
    match operation {
        Ed448Operation::SoftwareKeyGeneration | Ed448Operation::SoftwareKeyImport => Ok(()),
        Ed448Operation::Verify | Ed448Operation::OpaqueSign => {
            #[cfg(all(feature = "ed448-openssl", not(target_arch = "wasm32")))]
            if !crate::native_provider::is_available() {
                return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
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
    fn sign_message(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], CryptoError>;
}

/// Obtain an opaque signature and verify its key association and exact message
/// before returning it. Unsupported targets fail before calling the provider.
pub fn sign_with_provider(
    provider: &impl OpaqueEd448Signer,
    message: &[u8],
) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
    require_support(Ed448Operation::OpaqueSign)?;
    let public = provider.public_key();
    let signature = provider.sign_message(message)?;
    verify(public, message, &signature)?;
    Ok(signature)
}
