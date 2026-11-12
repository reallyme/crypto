// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    digest::with_digest, verify, EcdsaCurve, EcdsaEncoding, EcdsaError, EcdsaHash, EcdsaInput,
};

/// Non-exporting platform signing boundary. The provider receives a digest
/// exactly once and must return the explicitly requested signature encoding.
pub trait OpaqueEcdsaSigner {
    /// Curve of the associated opaque private key.
    fn curve(&self) -> EcdsaCurve;
    /// SEC1 public key associated with that private key.
    fn public_key(&self) -> &[u8];
    /// Sign the provided prehash, without hashing it again.
    fn sign_prehash(
        &self,
        hash: EcdsaHash,
        digest: &[u8],
        encoding: EcdsaEncoding,
    ) -> Result<Vec<u8>, EcdsaError>;
}

/// Hash a message once or validate its prehash, request an opaque signature,
/// then verify the provider's encoding, key association and exact input.
pub fn sign_with_provider(
    provider: &impl OpaqueEcdsaSigner,
    input: EcdsaInput<'_>,
    encoding: EcdsaEncoding,
) -> Result<Vec<u8>, EcdsaError> {
    let curve = provider.curve();
    let public = provider.public_key();
    super::verify::validate_public_key(curve, public)?;
    with_digest(input, |hash, bytes| {
        let signature = provider.sign_prehash(hash, bytes, encoding)?;
        verify(
            curve,
            public,
            EcdsaInput::Prehash { hash, bytes },
            &signature,
            encoding,
        )?;
        Ok(signature)
    })
}
