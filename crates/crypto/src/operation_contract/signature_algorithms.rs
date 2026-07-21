// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Signature-specific generated algorithm mapping.

use buffa::{EnumValue, MessageField, ProtoBox};
use crypto_core::Algorithm;
#[cfg(feature = "rsa")]
use crypto_proto::generated::proto::reallyme::crypto::v1::RsaPublicKeyDerEncoding;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    CryptoAlgorithmIdentifier, SignatureAlgorithm,
};
use crypto_proto::wire::CryptoWireError;

use super::identifier::algorithm_branch;
use super::wire_error::invalid_parameter;
use super::wire_error::unsupported_algorithm;

pub(super) fn signature_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<Algorithm, CryptoWireError> {
    signature_algorithm_value(identifier)
        .and_then(|value| Algorithm::try_from(value).map_err(|_| unsupported_algorithm()))
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
    match encoding.as_known() {
        Some(RsaPublicKeyDerEncoding::RSA_PUBLIC_KEY_DER_ENCODING_PKCS1) => {
            Ok(crypto_rsa::RsaPublicKeyDerEncoding::Pkcs1)
        }
        Some(RsaPublicKeyDerEncoding::RSA_PUBLIC_KEY_DER_ENCODING_SPKI) => {
            Ok(crypto_rsa::RsaPublicKeyDerEncoding::Spki)
        }
        Some(RsaPublicKeyDerEncoding::RSA_PUBLIC_KEY_DER_ENCODING_UNSPECIFIED) | None => {
            Err(invalid_parameter())
        }
    }
}

pub(super) fn signature_identifier(algorithm: SignatureAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Signature(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}
