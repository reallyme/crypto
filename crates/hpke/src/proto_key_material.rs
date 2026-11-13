// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Existing ordinary HPKE key derivation contracts. Flexible IKM and exact
//! suite-width IKM remain distinct; neither imports live protocol state.

use crate::{HpkeError, HpkeKeyPair, HpkeSuite};
use buffa::MessageField;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoHpkeDeriveKeyPairRequest, CryptoHpkeExactWidthDeriveKeyPairRequest,
    CryptoHpkePublicKeyDescriptor, HpkeSuiteIdentifier,
};
use zeroize::Zeroize;

/// Reuse the existing flexible-IKM request and existing minimum 32-byte API.
/// Return its native private owner separately from the public descriptor.
pub fn derive_keypair_from_ikm(
    request: &CryptoHpkeDeriveKeyPairRequest,
) -> Result<(HpkeKeyPair, CryptoHpkePublicKeyDescriptor), HpkeError> {
    known(request.__buffa_unknown_fields.is_empty())?;
    let suite = algorithm(request.algorithm.as_option())?;
    derive(
        suite,
        &request.input_key_material,
        crate::derive_keypair_from_ikm,
    )
}

/// Preserve the exact-suite-private-width API, which differs from the existing
/// flexible-IKM executor for such suites as P384, P521, X448 and ML-KEM.
pub fn derive_keypair_exact(
    request: &CryptoHpkeExactWidthDeriveKeyPairRequest,
) -> Result<(HpkeKeyPair, CryptoHpkePublicKeyDescriptor), HpkeError> {
    known(request.__buffa_unknown_fields.is_empty())?;
    let suite = HpkeSuite::try_from(
        request
            .suite
            .as_option()
            .ok_or(HpkeError::PRIMITIVE_INVALID_PARAMETER)?,
    )?;
    derive(suite, &request.input_key_material, crate::derive_keypair)
}

fn derive(
    suite: HpkeSuite,
    ikm: &[u8],
    operation: fn(HpkeSuite, &[u8]) -> Result<HpkeKeyPair, HpkeError>,
) -> Result<(HpkeKeyPair, CryptoHpkePublicKeyDescriptor), HpkeError> {
    let suite_identifier = HpkeSuiteIdentifier::try_from(suite)?;
    let mut key = operation(suite, ikm)?;
    let mut output = CryptoHpkePublicKeyDescriptor {
        suite: MessageField::some(suite_identifier),
        public_key: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    if output
        .public_key
        .try_reserve_exact(key.public_key.len())
        .is_err()
    {
        key.public_key.zeroize();
        return Err(HpkeError::BACKEND_INTERNAL);
    }
    output.public_key.resize(key.public_key.len(), 0);
    output.public_key.copy_from_slice(&key.public_key);
    Ok((key, output))
}
fn known(value: bool) -> Result<(), HpkeError> {
    if value {
        Ok(())
    } else {
        Err(HpkeError::PRIMITIVE_INVALID_PARAMETER)
    }
}
fn algorithm(value: Option<&CryptoAlgorithmIdentifier>) -> Result<HpkeSuite, HpkeError> {
    let value = value.ok_or(HpkeError::PRIMITIVE_INVALID_PARAMETER)?;
    known(value.__buffa_unknown_fields.is_empty())?;
    match value.algorithm.as_ref() {
        Some(Algorithm::HpkeSuite(suite)) => HpkeSuite::try_from(suite.as_ref()),
        _ => Err(HpkeError::PRIMITIVE_INVALID_PARAMETER),
    }
}
