// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Existing multikey transforms with protected identifiers and JWK owners.

use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoJwkToMultikeyRequest, CryptoJwkToMultikeyResult, CryptoMultikeyToJwkRequest,
    CryptoMultikeyToJwkResult, PublicJwk,
};
use envelopes_jwk::{
    proto_options::{ProtectedJwk, ProtectedJwkOptions},
    JwkOptions,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns a validated public JWK without an alternative parser.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct JwkToMultikeyInputs {
    jwk: ProtectedJwk,
}
impl JwkToMultikeyInputs {
    /// Keeps the existing reviewed codec names and exact support policy.
    pub fn multikey(&self) -> Result<CryptoJwkToMultikeyResult, CryptoError> {
        let encoded = Zeroizing::new(crate::jwk_to_multikey(self.jwk.as_jwk())?);
        u32::try_from(encoded.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let mut output = CryptoJwkToMultikeyResult::default();
        output
            .multikey
            .try_reserve_exact(encoded.len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        output.multikey.extend_from_slice(encoded.as_bytes())?;
        Ok(output)
    }
}
impl TryFrom<&CryptoJwkToMultikeyRequest> for JwkToMultikeyInputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoJwkToMultikeyRequest) -> Result<Self, Self::Error> {
        let jwk = value
            .jwk
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        if let Some(crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::public_jwk::Key::Ec(ec)) = jwk.key.as_ref() {
            // Keep this adapter's own native gate even if a sibling enables
            // the JWK dependency's backend through Cargo feature unification.
            return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
        Ok(Self {
            jwk: ProtectedJwk::try_from(jwk)?,
        })
    }
}
/// Owns exact UTF-8 multikey bytes and the caller-selected JWK options.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MultikeyToJwkInputs {
    multikey: Zeroizing<String>,
    options: ProtectedJwkOptions,
}
impl MultikeyToJwkInputs {
    /// Uses only the existing multikey parser and native JWK encoder policy.
    pub fn jwk(&self) -> Result<ProtectedJwk, CryptoError> {
        let options = self.options.as_options();
        let selection = JwkOptions {
            alg: options.alg,
            use_sig: options.use_sig,
            use_enc: options.use_enc,
            kid: None,
        };
        ProtectedJwk::try_from(crate::multikey_to_jwk(&self.multikey, selection)?)?
            .with_key_id(options.kid.as_deref())
    }
    /// Returns the typed model without exporting unguarded strings.
    pub fn jwk_result(&self) -> Result<CryptoMultikeyToJwkResult, CryptoError> {
        let owner = self.jwk()?;
        Ok(CryptoMultikeyToJwkResult {
            jwk: MessageField::some(PublicJwk::try_from(owner.as_jwk())?),
        })
    }
}
impl TryFrom<&CryptoMultikeyToJwkRequest> for MultikeyToJwkInputs {
    type Error = CryptoError;
    fn try_from(value: &CryptoMultikeyToJwkRequest) -> Result<Self, Self::Error> {
        u32::try_from(value.multikey.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let text = core::str::from_utf8(&value.multikey)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_ENCODING)?;
        let options = ProtectedJwkOptions::try_from(
            value
                .options
                .as_option()
                .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
        )?;
        let mut multikey = Zeroizing::new(String::new());
        multikey
            .try_reserve_exact(text.len())
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        multikey.push_str(text);
        Ok(Self { multikey, options })
    }
}
