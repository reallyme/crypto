// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic KEM inputs for conformance, distinct from randomized requests.
//! Existing native/WASM feature and typed-error policies remain authoritative.

use crate::native_contract_support::known_fields;
use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity, CryptoAlgorithmIdentifier,
    CryptoKemConformanceEncapsulateRequest, CryptoKemEncapsulation, KemAlgorithm,
};

fn algorithm(
    identifier: Option<&CryptoAlgorithmIdentifier>,
) -> Result<(Algorithm, KemAlgorithm), CryptoError> {
    let identifier = identifier.ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
    known_fields(identifier.__buffa_unknown_fields.is_empty())?;
    let Some(Identity::Kem(value)) = identifier.algorithm.as_ref() else {
        return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
    };
    let value = value
        .as_known()
        .filter(|value| *value != KemAlgorithm::KEM_ALGORITHM_UNSPECIFIED)
        .ok_or(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    Ok((Algorithm::try_from(identifier)?, value))
}

/// Invoke the existing explicit-coins ML-KEM/X-Wing operation with exact bytes.
/// No OS RNG, seed normalization or provider fallback is introduced here.
pub fn encapsulate(
    request: &CryptoKemConformanceEncapsulateRequest,
) -> Result<CryptoKemEncapsulation, CryptoError> {
    known_fields(request.__buffa_unknown_fields.is_empty())?;
    let (native, wire) = algorithm(request.algorithm.as_option())?;
    #[cfg(all(
        feature = "dispatch",
        any(feature = "native", feature = "wasm"),
        any(
            feature = "ml-kem-512",
            feature = "ml-kem-768",
            feature = "ml-kem-1024",
            feature = "x-wing"
        )
    ))]
    {
        let result = crate::operations::kem::encapsulate_derand(
            native,
            &request.public_key,
            &request.encapsulation_randomness,
        )?;
        let ciphertext = zeroize::Zeroizing::new(result.ciphertext);
        let mut output = CryptoKemEncapsulation {
            algorithm: buffa::MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(Identity::Kem(wire.into())),
                __buffa_unknown_fields: Default::default(),
            }),
            ciphertext: Vec::new(),
            shared_secret: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        };
        crate::native_contract_support::copy_bytes(&mut output.ciphertext, &ciphertext)?;
        crate::native_contract_support::copy_bytes(
            &mut output.shared_secret,
            &result.shared_secret,
        )?;
        Ok(output)
    }
    #[cfg(not(all(
        feature = "dispatch",
        any(feature = "native", feature = "wasm"),
        any(
            feature = "ml-kem-512",
            feature = "ml-kem-768",
            feature = "ml-kem-1024",
            feature = "x-wing"
        )
    )))]
    {
        let _ = (native, wire);
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}
