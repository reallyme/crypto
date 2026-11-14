// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Existing raw-key encoders with protected metadata and result ownership.

use crate::proto_options::{ProtectedJwk, ProtectedJwkOptions};
use crate::{Jwk, JwkOptions};
use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPublicKeyToJcsResult, CryptoPublicKeyToJwkRequest, CryptoPublicKeyToJwkResult,
    KeyAlgorithm, PublicJwk,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns public-key bytes and options without another algorithm vocabulary.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PublicKeyToJwkInputs {
    #[zeroize(skip)]
    algorithm: KeyAlgorithm,
    public_key: Zeroizing<Vec<u8>>,
    options: ProtectedJwkOptions,
}
impl PublicKeyToJwkInputs {
    /// Keeps KID absent during legacy by-value encoding, then copies it only
    /// after the returned JWK has entered its final clearing owner.
    pub fn jwk(&self) -> Result<ProtectedJwk, CryptoError> {
        let options = self.options.as_options();
        let selection = JwkOptions {
            alg: options.alg,
            use_sig: options.use_sig,
            use_enc: options.use_enc,
            kid: None,
        };
        let owned =
            ProtectedJwk::try_from(match self.algorithm {
                KeyAlgorithm::KEY_ALGORITHM_ED25519 => {
                    Jwk::Okp(crate::ed25519_public_key_to_jwk(&self.public_key, selection)?.into())
                }
                KeyAlgorithm::KEY_ALGORITHM_X25519 => {
                    Jwk::Okp(crate::x25519_public_key_to_jwk(&self.public_key, selection)?.into())
                }
                KeyAlgorithm::KEY_ALGORITHM_P256 => {
                    Jwk::Ec(crate::p256_public_key_to_jwk(&self.public_key, selection)?)
                }
                KeyAlgorithm::KEY_ALGORITHM_SECP256K1 => Jwk::Ec(
                    crate::secp256k1_public_key_to_jwk(&self.public_key, selection)?,
                ),
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44 => Jwk::Akp(
                    crate::mldsa44_public_key_to_jwk(&self.public_key, selection)?,
                ),
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65 => Jwk::Akp(
                    crate::mldsa65_public_key_to_jwk(&self.public_key, selection)?,
                ),
                KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87 => {
                    Jwk::Akp(crate::mldsa87_public_key_to_jwk(&self.public_key, selection)?.into())
                }
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512 => Jwk::Akp(
                    crate::mlkem512_public_key_to_jwk(&self.public_key, selection)?,
                ),
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768 => Jwk::Akp(
                    crate::mlkem768_public_key_to_jwk(&self.public_key, selection)?,
                ),
                KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024 => Jwk::Akp(
                    crate::mlkem1024_public_key_to_jwk(&self.public_key, selection)?.into(),
                ),
                KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S => Jwk::Akp(
                    crate::slh_dsa_sha2_128s_public_key_to_jwk(&self.public_key, selection)?,
                ),
                KeyAlgorithm::KEY_ALGORITHM_X_WING_768 => Jwk::Akp(
                    crate::x_wing_768_public_key_to_jwk(&self.public_key, selection)?,
                ),
                KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED
                | KeyAlgorithm::KEY_ALGORITHM_P384
                | KeyAlgorithm::KEY_ALGORITHM_P521 => {
                    return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
                }
            })?;
        owned.with_key_id(options.kid.as_deref())
    }
    /// Returns the established typed JWK boundary representation.
    pub fn jwk_result(&self) -> Result<CryptoPublicKeyToJwkResult, CryptoError> {
        let owner = self.jwk()?;
        Ok(CryptoPublicKeyToJwkResult {
            jwk: MessageField::some(PublicJwk::try_from(owner.as_jwk())?),
        })
    }
    /// Reuses the existing trusted JCS algorithm without parsing or normalizing
    /// JSON text. Intermediate and output copies remain under clearing owners.
    pub fn canonical_jcs(&self) -> Result<CryptoPublicKeyToJcsResult, CryptoError> {
        let owner = self.jwk()?;
        let canonical = Zeroizing::new(crate::canonicalize_jwk::canonicalize_jwk(owner.as_jwk())?);
        u32::try_from(canonical.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let mut output = CryptoPublicKeyToJcsResult::default();
        output
            .canonical_jcs
            .try_reserve_exact(canonical.len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        output
            .canonical_jcs
            .extend_from_slice(canonical.as_bytes())?;
        Ok(output)
    }
}
impl TryFrom<&CryptoPublicKeyToJwkRequest> for PublicKeyToJwkInputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoPublicKeyToJwkRequest) -> Result<Self, Self::Error> {
        let algorithm = value
            .algorithm
            .as_known()
            .ok_or(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
        match algorithm {
            KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED
            | KeyAlgorithm::KEY_ALGORITHM_P384
            | KeyAlgorithm::KEY_ALGORITHM_P521 => {
                return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            }
            _ => {}
        }
        u32::try_from(value.public_key.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let options = ProtectedJwkOptions::try_from(
            value
                .options
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        let mut public_key = Zeroizing::new(Vec::new());
        public_key
            .try_reserve_exact(value.public_key.len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        public_key.extend_from_slice(&value.public_key);
        Ok(Self {
            algorithm,
            public_key,
            options,
        })
    }
}
