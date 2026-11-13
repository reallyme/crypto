// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared generated algorithm-identifier validation.

use buffa::{MessageField, ProtoBox};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    CryptoAlgorithmIdentifier,
};
use crypto_proto::wire::CryptoWireError;

use super::wire_error::invalid_parameter;
#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305",
    feature = "sha2",
    feature = "sha3",
    feature = "hmac",
    feature = "aes-kw",
    all(
        feature = "dispatch",
        any(
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "rsa",
            feature = "secp256k1",
            feature = "x25519",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "ml-kem-512",
            feature = "ml-kem-768",
            feature = "ml-kem-1024",
            feature = "slh-dsa",
            feature = "x-wing"
        )
    )
))]
use super::wire_error::unsupported_algorithm;

pub(super) fn algorithm_branch(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<&ProtoAlgorithmBranch, CryptoWireError> {
    identifier
        .as_option()
        .and_then(|identifier| identifier.algorithm.as_ref())
        .ok_or_else(invalid_parameter)
}

#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305",
    feature = "sha2",
    feature = "sha3",
    feature = "hmac",
    feature = "aes-kw",
    all(
        feature = "dispatch",
        any(
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "rsa",
            feature = "secp256k1",
            feature = "x25519",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "ml-kem-512",
            feature = "ml-kem-768",
            feature = "ml-kem-1024",
            feature = "slh-dsa",
            feature = "x-wing"
        )
    )
))]
pub(super) fn native_identity<T>(
    identifier: &MessageField<CryptoAlgorithmIdentifier, impl ProtoBox<CryptoAlgorithmIdentifier>>,
) -> Result<T, CryptoWireError>
where
    for<'a> T: TryFrom<
        &'a CryptoAlgorithmIdentifier,
        Error = crypto_proto::convert::UnsupportedProtoAlgorithm,
    >,
{
    let identifier = identifier.as_option().ok_or_else(invalid_parameter)?;
    T::try_from(identifier).map_err(|_| unsupported_algorithm())
}
