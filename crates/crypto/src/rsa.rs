// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RSA signature verification facade over the semantic operation owner.

use crypto_core::CryptoError;

pub use crypto_rsa::{
    RsaHash, RsaPssParams, RsaPublicKeyDerEncoding, RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS,
    RSA_PUBLIC_KEY_DER_MAX_LEN, RSA_SIGNATURE_MAX_LEN,
};

/// Verifies an RSASSA-PKCS1-v1_5 signature.
pub fn verify_rsa_pkcs1v15(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    hash: RsaHash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify_rsa_pkcs1v15(
        public_key_der,
        encoding,
        hash,
        message,
        signature,
    )
}

/// Verifies an RSASSA-PSS signature.
pub fn verify_rsa_pss(
    public_key_der: &[u8],
    encoding: RsaPublicKeyDerEncoding,
    params: RsaPssParams,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify_rsa_pss(
        public_key_der,
        encoding,
        params,
        message,
        signature,
    )
}

/// Public RSA material suitable for JWK publication.
pub use crypto_rsa::RsaSigningPublicKey;

/// Shared signing boundary with zeroizing private-key ownership.
pub struct RsaSigningKey(crypto_rsa::RsaSigningKey);

impl zeroize::ZeroizeOnDrop for RsaSigningKey {}

impl RsaSigningKey {
    /// Imports and validates a 2048..8192-bit PKCS#8 RSA signing key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let _policy = crate::secret_material::bind_operation_policy(
            crate::secret_material::SecretMaterialOperation::SignatureKeyDerivation,
        );
        crypto_rsa::RsaSigningKey::from_pkcs8_der(der).map(Self)
    }

    /// Returns canonical public components without exporting private state.
    pub fn public_key(&self) -> Result<RsaSigningPublicKey, CryptoError> {
        self.0.public_key()
    }

    /// Computes a blinded RSASSA-PKCS1-v1_5 SHA-256 signature.
    pub fn sign_rs256(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let _policy = crate::secret_material::bind_operation_policy(
            crate::secret_material::SecretMaterialOperation::SignatureSign,
        );
        self.0.sign_rs256(message)
    }
}

/// Strict SHA-2 PSS DER import for certificate signature parameters.
pub use crypto_rsa::parse_rsa_pss_sha2_params;
