// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone generation through the existing key-agreement semantic owner.
//!
//! The request does not extend executable operation oneofs or select a provider.
//! Its native operation already returns exportable key material under the
//! KeyAgreementKeyGeneration policy; opaque private owners are not exported.

use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Branch,
    CryptoKeyAgreementGenerateKeyPairRequest, CryptoKeyPair,
};

/// Generate a keypair through the unchanged semantic key-agreement operation.
/// Family and identity validation are explicit even in a disabled feature lane.
/// Native provider/entropy failures propagate as their original canonical error.
pub fn generate_key_pair(
    request: &CryptoKeyAgreementGenerateKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoError> {
    crate::native_contract_support::known_fields(request.__buffa_unknown_fields.is_empty())?;
    let identifier = request
        .algorithm
        .as_option()
        .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    crate::native_contract_support::known_fields(identifier.__buffa_unknown_fields.is_empty())?;
    let value = match identifier.algorithm.as_ref() {
        Some(Branch::KeyAgreement(value)) => *value,
        _ => return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
    };
    // Reuse the same total owner-local identity conversion as existing derive
    // routes; no signature-family alias or hand-maintained algorithm table.
    let algorithm =
        Algorithm::try_from(identifier).map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    #[cfg(all(
        feature = "dispatch",
        any(feature = "native", feature = "wasm"),
        any(
            feature = "x25519",
            feature = "p256",
            feature = "p384",
            feature = "p521"
        )
    ))]
    {
        use crate::native_contract_support::copy_bytes;
        use buffa::MessageField;
        use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoAlgorithmIdentifier;
        let pair = crate::operations::key_agreement::generate_key_pair(algorithm)?;
        // The native secret field stays in its original guard. Guard its public
        // association too while either fallible destination copy can fail.
        let public = zeroize::Zeroizing::new(pair.public_key);
        let mut result = CryptoKeyPair {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(Branch::KeyAgreement(value)),
                __buffa_unknown_fields: Default::default(),
            }),
            public_key: Vec::new(),
            secret_key: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        };
        copy_bytes(&mut result.public_key, &public)?;
        copy_bytes(&mut result.secret_key, &pair.secret_key)?;
        Ok(result)
    }
    #[cfg(not(all(
        feature = "dispatch",
        any(feature = "native", feature = "wasm"),
        any(
            feature = "x25519",
            feature = "p256",
            feature = "p384",
            feature = "p521"
        )
    )))]
    {
        let _ = (algorithm, value);
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}
