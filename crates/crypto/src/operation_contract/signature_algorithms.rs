// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature-specific generated algorithm mapping.

use buffa::{EnumValue, MessageField, ProtoBox};
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    CryptoAlgorithmIdentifier, SignatureAlgorithm,
};
#[cfg(feature = "rsa")]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoRsaPublicKeyDerEncodingIdentifier, RsaPublicKeyDerEncoding,
};
use crypto_proto::wire::CryptoWireError;

use super::identifier::{algorithm_branch, native_identity};
use super::wire_error::invalid_parameter;
use super::wire_error::unsupported_algorithm;

pub(super) fn signature_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<Algorithm, CryptoWireError> {
    signature_algorithm_value(identifier)?;
    native_identity(identifier)
}

pub(super) fn signature_algorithm_value(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<SignatureAlgorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Signature(value) => {
            value.as_known().ok_or_else(unsupported_algorithm)
        }
        _ => Err(invalid_parameter()),
    }
}

#[cfg(feature = "rsa")]
pub(super) fn rsa_public_key_der_encoding(
    encoding: EnumValue<RsaPublicKeyDerEncoding>,
) -> Result<crypto_rsa::RsaPublicKeyDerEncoding, CryptoWireError> {
    let identity = CryptoRsaPublicKeyDerEncodingIdentifier {
        encoding,
        __buffa_unknown_fields: Default::default(),
    };
    crypto_rsa::RsaPublicKeyDerEncoding::try_from(&identity).map_err(|_| invalid_parameter())
}

pub(super) fn signature_identifier(algorithm: SignatureAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Signature(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}
