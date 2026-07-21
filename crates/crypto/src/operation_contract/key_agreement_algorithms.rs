// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Key-agreement-specific generated algorithm mapping.

use buffa::{EnumValue, MessageField, ProtoBox};
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    CryptoAlgorithmIdentifier, KeyAgreementAlgorithm,
};
use crypto_proto::wire::CryptoWireError;

use super::identifier::algorithm_branch;
use super::wire_error::invalid_parameter;
use super::wire_error::unsupported_algorithm;

pub(super) fn key_agreement_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<Algorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::KeyAgreement(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| Algorithm::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

pub(super) fn key_agreement_identifier(
    algorithm: KeyAgreementAlgorithm,
) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::KeyAgreement(EnumValue::from(
            algorithm,
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}
