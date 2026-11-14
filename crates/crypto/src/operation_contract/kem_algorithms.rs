// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! KEM-specific generated algorithm mapping.

use buffa::{EnumValue, MessageField, ProtoBox};
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    CryptoAlgorithmIdentifier, KemAlgorithm,
};
use crypto_proto::wire::CryptoWireError;

use super::identifier::{algorithm_branch, native_identity};
use super::wire_error::invalid_parameter;

pub(super) fn kem_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<Algorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Kem(_) => native_identity(identifier),
        _ => Err(invalid_parameter()),
    }
}

pub(super) fn kem_identifier(algorithm: KemAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Kem(EnumValue::from(algorithm))),
    }
}
