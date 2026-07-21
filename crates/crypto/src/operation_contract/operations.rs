// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Operation-specific protobuf execution functions.
#[cfg(all(
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "dispatch"
    ),
    any(feature = "native", feature = "wasm")
))]
use buffa::MessageField;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
use crypto_proto::convert::kem_algorithm_to_proto;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521"
    )
))]
use crypto_proto::convert::key_agreement_algorithm_to_proto;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoKeyPair;
#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    AeadAlgorithm as ProtoAead, CryptoAeadOpenRequest, CryptoAeadOpenResult, CryptoAeadSealRequest,
    CryptoAeadSealResult,
};
#[cfg(all(
    any(feature = "sha2", feature = "sha3"),
    any(feature = "native", feature = "wasm")
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHashRequest, CryptoHashResult, HashAlgorithm as ProtoHash,
};
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKemDecapsulateRequest, CryptoKemDecapsulateResult, CryptoKemDeriveKeyPairRequest,
    CryptoKemEncapsulateRequest, CryptoKemEncapsulation, CryptoKemGenerateKeyPairRequest,
};
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521"
    )
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKeyAgreementDeriveKeyPairRequest, CryptoKeyAgreementDeriveSharedSecretRequest,
    CryptoKeyAgreementDeriveSharedSecretResult,
};
#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKeyUnwrapRequest, CryptoKeyUnwrapResult, CryptoKeyWrapRequest, CryptoKeyWrapResult,
};
#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoMacAuthenticateRequest, CryptoMacAuthenticateResult, CryptoMacVerifyRequest,
    CryptoVerificationResult,
};
#[cfg(any(
    all(
        any(
            feature = "sha2",
            feature = "sha3",
            feature = "aes",
            feature = "aes-gcm-siv",
            feature = "chacha20-poly1305",
            feature = "hmac",
            feature = "aes-kw"
        ),
        any(feature = "native", feature = "wasm")
    ),
    all(feature = "dispatch", any(feature = "native", feature = "wasm"))
))]
use crypto_proto::wire::CryptoWireError;

#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
use super::algorithms::{aead_algorithm, aead_identifier};
#[cfg(all(
    any(feature = "sha2", feature = "sha3"),
    any(feature = "native", feature = "wasm")
))]
use super::algorithms::{hash_algorithm, hash_identifier};
#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
use super::algorithms::{key_wrap_algorithm, key_wrap_identifier};
#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
use super::algorithms::{mac_algorithm, mac_identifier, proto_mac_algorithm};
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
use super::kem_algorithms::{kem_algorithm, kem_identifier};
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521"
    )
))]
use super::key_agreement_algorithms::{key_agreement_algorithm, key_agreement_identifier};
#[cfg(any(
    all(
        any(
            feature = "sha2",
            feature = "sha3",
            feature = "aes",
            feature = "aes-gcm-siv",
            feature = "chacha20-poly1305",
            feature = "hmac",
            feature = "aes-kw"
        ),
        any(feature = "native", feature = "wasm")
    ),
    all(feature = "dispatch", any(feature = "native", feature = "wasm"))
))]
use super::operation_error::map_operation_error;
#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
use super::operation_error::{is_operation_verification_mismatch, verification_result};
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
use super::wire_error::invalid_parameter;
#[cfg(all(
    any(feature = "sha2", feature = "sha3"),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn process_hash(
    request: CryptoHashRequest,
) -> Result<CryptoHashResult, CryptoWireError> {
    let algorithm = hash_algorithm(&request.algorithm)?;
    let digest =
        crate::operations::hash::digest(algorithm, &request.input).map_err(map_operation_error)?;
    let result = CryptoHashResult {
        algorithm: MessageField::some(hash_identifier(ProtoHash::from(algorithm))),
        digest,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn process_aead_seal(
    request: CryptoAeadSealRequest,
) -> Result<CryptoAeadSealResult, CryptoWireError> {
    let algorithm = aead_algorithm(&request.algorithm)?;
    let ciphertext_with_tag = crate::operations::aead::seal(
        algorithm,
        &request.key,
        &request.nonce,
        &request.aad,
        &request.plaintext,
    )
    .map_err(map_operation_error)?;
    let result = CryptoAeadSealResult {
        algorithm: MessageField::some(aead_identifier(ProtoAead::from(algorithm))),
        ciphertext_with_tag,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(
    any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ),
    any(feature = "native", feature = "wasm")
))]
pub(super) fn process_aead_open(
    request: CryptoAeadOpenRequest,
) -> Result<CryptoAeadOpenResult, CryptoWireError> {
    let algorithm = aead_algorithm(&request.algorithm)?;
    let plaintext = crate::operations::aead::open(
        algorithm,
        &request.key,
        &request.nonce,
        &request.aad,
        &request.ciphertext_with_tag,
    )
    .map_err(map_operation_error)?;
    let result = CryptoAeadOpenResult {
        algorithm: MessageField::some(aead_identifier(ProtoAead::from(algorithm))),
        plaintext: plaintext.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
pub(super) fn process_mac_authenticate(
    request: CryptoMacAuthenticateRequest,
) -> Result<CryptoMacAuthenticateResult, CryptoWireError> {
    let algorithm = mac_algorithm(&request.algorithm)?;
    let tag = crate::operations::mac::authenticate(algorithm, &request.key, &request.message)
        .map_err(map_operation_error)?;
    let result = CryptoMacAuthenticateResult {
        algorithm: MessageField::some(mac_identifier(proto_mac_algorithm(algorithm))),
        tag,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
pub(super) fn process_mac_verify(
    request: CryptoMacVerifyRequest,
) -> Result<CryptoVerificationResult, CryptoWireError> {
    let algorithm = mac_algorithm(&request.algorithm)?;
    let verification = match crate::operations::mac::verify(
        algorithm,
        &request.key,
        &request.message,
        &request.tag,
    ) {
        Ok(()) => verification_result(mac_identifier(proto_mac_algorithm(algorithm)), true, None),
        Err(error) if is_operation_verification_mismatch(&error) => {
            verification_result(mac_identifier(proto_mac_algorithm(algorithm)), false, None)
        }
        Err(error) => verification_result(
            mac_identifier(proto_mac_algorithm(algorithm)),
            false,
            Some(map_operation_error(error)),
        ),
    };
    Ok(verification)
}

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521"
    )
))]
pub(super) fn process_key_agreement_derive_shared_secret(
    request: CryptoKeyAgreementDeriveSharedSecretRequest,
) -> Result<CryptoKeyAgreementDeriveSharedSecretResult, CryptoWireError> {
    let algorithm = key_agreement_algorithm(&request.algorithm)?;
    let shared_secret = crate::operations::key_agreement::derive_shared_secret(
        algorithm,
        &request.secret_key,
        &request.public_key,
    )
    .map_err(map_operation_error)?;
    let proto_algorithm =
        key_agreement_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKeyAgreementDeriveSharedSecretResult {
        algorithm: MessageField::some(key_agreement_identifier(proto_algorithm)),
        shared_secret: shared_secret.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521"
    )
))]
pub(super) fn process_key_agreement_derive_key_pair(
    request: CryptoKeyAgreementDeriveKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoWireError> {
    let algorithm = key_agreement_algorithm(&request.algorithm)?;
    let key_pair =
        crate::operations::key_agreement::derive_key_pair(algorithm, &request.secret_key)
            .map_err(map_operation_error)?;
    let proto_algorithm =
        key_agreement_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKeyPair {
        algorithm: MessageField::some(key_agreement_identifier(proto_algorithm)),
        public_key: key_pair.public_key,
        secret_key: key_pair.secret_key.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
pub(super) fn process_kem_generate_key_pair(
    request: CryptoKemGenerateKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoWireError> {
    let algorithm = kem_algorithm(&request.algorithm)?;
    let key_pair =
        crate::operations::kem::generate_key_pair(algorithm).map_err(map_operation_error)?;
    let proto_algorithm = kem_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKeyPair {
        algorithm: MessageField::some(kem_identifier(proto_algorithm)),
        public_key: key_pair.public_key,
        secret_key: key_pair.secret_key.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
pub(super) fn process_kem_derive_key_pair(
    request: CryptoKemDeriveKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoWireError> {
    let algorithm = kem_algorithm(&request.algorithm)?;
    let key_pair = crate::operations::kem::derive_key_pair(algorithm, &request.secret_key)
        .map_err(map_operation_error)?;
    let proto_algorithm = kem_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKeyPair {
        algorithm: MessageField::some(kem_identifier(proto_algorithm)),
        public_key: key_pair.public_key,
        secret_key: key_pair.secret_key.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
pub(super) fn process_kem_encapsulate(
    request: CryptoKemEncapsulateRequest,
) -> Result<CryptoKemEncapsulation, CryptoWireError> {
    let algorithm = kem_algorithm(&request.algorithm)?;
    let encapsulation = crate::operations::kem::encapsulate(algorithm, &request.public_key)
        .map_err(map_operation_error)?;
    let proto_algorithm = kem_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKemEncapsulation {
        algorithm: MessageField::some(kem_identifier(proto_algorithm)),
        ciphertext: encapsulation.ciphertext,
        shared_secret: encapsulation.shared_secret.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
pub(super) fn process_kem_decapsulate(
    request: CryptoKemDecapsulateRequest,
) -> Result<CryptoKemDecapsulateResult, CryptoWireError> {
    let algorithm = kem_algorithm(&request.algorithm)?;
    let shared_secret =
        crate::operations::kem::decapsulate(algorithm, &request.ciphertext, &request.secret_key)
            .map_err(map_operation_error)?;
    let proto_algorithm = kem_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKemDecapsulateResult {
        algorithm: MessageField::some(kem_identifier(proto_algorithm)),
        shared_secret: shared_secret.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
pub(super) fn process_key_wrap(
    request: CryptoKeyWrapRequest,
) -> Result<CryptoKeyWrapResult, CryptoWireError> {
    let algorithm = key_wrap_algorithm(&request.algorithm)?;
    let wrapped_key = crate::operations::key_wrap::wrap_key(
        algorithm,
        &request.wrapping_key,
        &request.key_to_wrap,
    )
    .map_err(map_operation_error)?;
    let result = CryptoKeyWrapResult {
        algorithm: MessageField::some(key_wrap_identifier(algorithm)),
        wrapped_key: wrapped_key.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(feature = "aes-kw", any(feature = "native", feature = "wasm")))]
pub(super) fn process_key_unwrap(
    request: CryptoKeyUnwrapRequest,
) -> Result<CryptoKeyUnwrapResult, CryptoWireError> {
    let algorithm = key_wrap_algorithm(&request.algorithm)?;
    let key = crate::operations::key_wrap::unwrap_key(
        algorithm,
        &request.wrapping_key,
        &request.wrapped_key,
    )
    .map_err(map_operation_error)?;
    let result = CryptoKeyUnwrapResult {
        algorithm: MessageField::some(key_wrap_identifier(algorithm)),
        key: key.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}
