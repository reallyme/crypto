// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Executable protobuf operation boundary.
//!
//! Native SDK methods remain the ergonomic public API. This module provides the
//! service-adapter lane: callers pass a stable operation id plus serialized
//! request protobuf bytes and receive a
//! [`CryptoProtoResult`](crypto_proto::wire::CryptoProtoResult) whose bytes are
//! either a successful result protobuf or a structured
//! [`CryptoError`](crypto_proto::generated::proto::reallyme::crypto::v1::CryptoError)
//! protobuf.
//! That mirrors Codec's process-proto boundary while still routing through the
//! same dispatch contracts used by the Rust SDK.
//!
//! Operation ids are sourced from the generated protobuf enum. The public C
//! constants are checked against these values in the FFI contract tests so the
//! numeric ABI and Connect schema cannot drift independently.

use buffa::{EnumValue, Message, MessageField};
use crypto_core::{
    AeadAlgorithm as CoreAead, Algorithm, ConstantTimeFailureKind, CryptoError,
    HashAlgorithm as CoreHash, MacAlgorithm, MacFailureKind, SignatureFailureKind,
};
use crypto_dispatch::{self, AeadParams, AlgorithmError, MacParams};
use crypto_proto::convert::{
    kem_algorithm_to_proto, key_agreement_algorithm_to_proto, signature_algorithm_to_proto,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    AeadAlgorithm as ProtoAead, CryptoAeadOpenRequest, CryptoAeadOpenResult, CryptoAeadSealRequest,
    CryptoAeadSealResult, CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHashRequest,
    CryptoHashResult, CryptoKemDecapsulateRequest, CryptoKemDecapsulateResult,
    CryptoKemEncapsulateRequest, CryptoKemEncapsulation, CryptoKemGenerateKeyPairRequest,
    CryptoKeyAgreementDeriveSharedSecretRequest, CryptoKeyAgreementDeriveSharedSecretResult,
    CryptoKeyPair, CryptoMacAuthenticateRequest, CryptoMacAuthenticateResult,
    CryptoMacVerifyRequest, CryptoOperation, CryptoSignatureGenerateKeyPairRequest,
    CryptoSignatureSignRequest, CryptoSignatureSignResult, CryptoSignatureVerifyRequest,
    CryptoVerificationResult, CryptoVerificationStatus, HashAlgorithm as ProtoHash, KemAlgorithm,
    KeyAgreementAlgorithm, MacAlgorithm as ProtoMac, SignatureAlgorithm,
};
use crypto_proto::wire::{
    decode_protobuf, CryptoProtoResult, CryptoWireError, CryptoWireErrorBranch,
};
use zeroize::Zeroize;

/// Process a [`CryptoHashRequest`] and return a [`CryptoHashResult`] envelope.
pub const OP_HASH: u32 = CryptoOperation::CRYPTO_OPERATION_HASH as u32;
/// Process a [`CryptoAeadSealRequest`] and return a [`CryptoAeadSealResult`] envelope.
pub const OP_AEAD_SEAL: u32 = CryptoOperation::CRYPTO_OPERATION_AEAD_SEAL as u32;
/// Process a [`CryptoAeadOpenRequest`] and return a [`CryptoAeadOpenResult`] envelope.
pub const OP_AEAD_OPEN: u32 = CryptoOperation::CRYPTO_OPERATION_AEAD_OPEN as u32;
/// Process a [`CryptoMacAuthenticateRequest`] and return a [`CryptoMacAuthenticateResult`] envelope.
pub const OP_MAC_AUTHENTICATE: u32 = CryptoOperation::CRYPTO_OPERATION_MAC_AUTHENTICATE as u32;
/// Process a [`CryptoMacVerifyRequest`] and return a [`CryptoVerificationResult`] envelope.
pub const OP_MAC_VERIFY: u32 = CryptoOperation::CRYPTO_OPERATION_MAC_VERIFY as u32;
/// Process a [`CryptoSignatureGenerateKeyPairRequest`] and return a [`CryptoKeyPair`] envelope.
pub const OP_SIGNATURE_GENERATE_KEY_PAIR: u32 =
    CryptoOperation::CRYPTO_OPERATION_SIGNATURE_GENERATE_KEY_PAIR as u32;
/// Reserved for the protobuf signature derive-key-pair request.
pub const OP_SIGNATURE_DERIVE_KEY_PAIR: u32 =
    CryptoOperation::CRYPTO_OPERATION_SIGNATURE_DERIVE_KEY_PAIR as u32;
/// Process a [`CryptoSignatureSignRequest`] and return a [`CryptoSignatureSignResult`] envelope.
pub const OP_SIGNATURE_SIGN: u32 = CryptoOperation::CRYPTO_OPERATION_SIGNATURE_SIGN as u32;
/// Process a [`CryptoSignatureVerifyRequest`] and return a [`CryptoVerificationResult`] envelope.
pub const OP_SIGNATURE_VERIFY: u32 = CryptoOperation::CRYPTO_OPERATION_SIGNATURE_VERIFY as u32;
/// Reserved for the protobuf BIP-340 Schnorr sign request.
pub const OP_BIP340_SCHNORR_SIGN: u32 =
    CryptoOperation::CRYPTO_OPERATION_BIP340_SCHNORR_SIGN as u32;
/// Reserved for the protobuf RSA verify request.
pub const OP_RSA_VERIFY: u32 = CryptoOperation::CRYPTO_OPERATION_RSA_VERIFY as u32;
/// Process a [`CryptoKeyAgreementDeriveSharedSecretRequest`] and return a result envelope.
pub const OP_KEY_AGREEMENT_DERIVE_SHARED_SECRET: u32 =
    CryptoOperation::CRYPTO_OPERATION_KEY_AGREEMENT_DERIVE_SHARED_SECRET as u32;
/// Reserved for the protobuf key-agreement derive-key-pair request.
pub const OP_KEY_AGREEMENT_DERIVE_KEY_PAIR: u32 =
    CryptoOperation::CRYPTO_OPERATION_KEY_AGREEMENT_DERIVE_KEY_PAIR as u32;
/// Process a [`CryptoKemGenerateKeyPairRequest`] and return a [`CryptoKeyPair`] envelope.
pub const OP_KEM_GENERATE_KEY_PAIR: u32 =
    CryptoOperation::CRYPTO_OPERATION_KEM_GENERATE_KEY_PAIR as u32;
/// Process a [`CryptoKemEncapsulateRequest`] and return a [`CryptoKemEncapsulation`] envelope.
pub const OP_KEM_ENCAPSULATE: u32 = CryptoOperation::CRYPTO_OPERATION_KEM_ENCAPSULATE as u32;
/// Process a [`CryptoKemDecapsulateRequest`] and return a [`CryptoKemDecapsulateResult`] envelope.
pub const OP_KEM_DECAPSULATE: u32 = CryptoOperation::CRYPTO_OPERATION_KEM_DECAPSULATE as u32;
/// Reserved for the protobuf HKDF derive request.
pub const OP_HKDF_DERIVE: u32 = CryptoOperation::CRYPTO_OPERATION_HKDF_DERIVE as u32;
/// Reserved for the protobuf generic KDF derive-key request.
pub const OP_KDF_DERIVE_KEY: u32 = CryptoOperation::CRYPTO_OPERATION_KDF_DERIVE_KEY as u32;
/// Reserved for the protobuf JWA Concat KDF request.
pub const OP_JWA_CONCAT_KDF_SHA256_DERIVE: u32 =
    CryptoOperation::CRYPTO_OPERATION_JWA_CONCAT_KDF_SHA256_DERIVE as u32;
/// Reserved for the protobuf key-wrap request.
pub const OP_KEY_WRAP: u32 = CryptoOperation::CRYPTO_OPERATION_KEY_WRAP as u32;
/// Reserved for the protobuf key-unwrap request.
pub const OP_KEY_UNWRAP: u32 = CryptoOperation::CRYPTO_OPERATION_KEY_UNWRAP as u32;
/// Reserved for the protobuf HPKE seal request.
pub const OP_HPKE_SEAL: u32 = CryptoOperation::CRYPTO_OPERATION_HPKE_SEAL as u32;
/// Reserved for the protobuf HPKE open request.
pub const OP_HPKE_OPEN: u32 = CryptoOperation::CRYPTO_OPERATION_HPKE_OPEN as u32;

/// Execute a protobuf-facing crypto operation.
pub fn process_proto(operation: u32, request_bytes: &[u8]) -> CryptoProtoResult {
    match process_proto_inner(operation, request_bytes) {
        Ok(result) => result,
        Err(error) => CryptoProtoResult::crypto_error(error),
    }
}

fn process_proto_inner(
    operation: u32,
    request_bytes: &[u8],
) -> Result<CryptoProtoResult, CryptoWireError> {
    match operation {
        OP_HASH => process_hash(request_bytes),
        OP_AEAD_SEAL => process_aead_seal(request_bytes),
        OP_AEAD_OPEN => process_aead_open(request_bytes),
        OP_MAC_AUTHENTICATE => process_mac_authenticate(request_bytes),
        OP_MAC_VERIFY => process_mac_verify(request_bytes),
        OP_SIGNATURE_GENERATE_KEY_PAIR => process_signature_generate_key_pair(request_bytes),
        OP_SIGNATURE_SIGN => process_signature_sign(request_bytes),
        OP_SIGNATURE_VERIFY => process_signature_verify(request_bytes),
        OP_KEY_AGREEMENT_DERIVE_SHARED_SECRET => {
            process_key_agreement_derive_shared_secret(request_bytes)
        }
        OP_KEM_GENERATE_KEY_PAIR => process_kem_generate_key_pair(request_bytes),
        OP_KEM_ENCAPSULATE => process_kem_encapsulate(request_bytes),
        OP_KEM_DECAPSULATE => process_kem_decapsulate(request_bytes),
        OP_SIGNATURE_DERIVE_KEY_PAIR
        | OP_BIP340_SCHNORR_SIGN
        | OP_RSA_VERIFY
        | OP_KEY_AGREEMENT_DERIVE_KEY_PAIR
        | OP_HKDF_DERIVE
        | OP_KDF_DERIVE_KEY
        | OP_JWA_CONCAT_KDF_SHA256_DERIVE
        | OP_KEY_WRAP
        | OP_KEY_UNWRAP
        | OP_HPKE_SEAL
        | OP_HPKE_OPEN => Err(unsupported_algorithm()),
        _ => Err(invalid_parameter()),
    }
}

fn process_hash(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode::<CryptoHashRequest>(request_bytes)?;
    let algorithm = hash_algorithm(&request.algorithm)?;
    let digest =
        crypto_dispatch::hash_digest(algorithm, &request.input).map_err(map_dispatch_error)?;
    let result = CryptoHashResult {
        algorithm: MessageField::some(hash_identifier(ProtoHash::from(algorithm))),
        digest,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(CryptoProtoResult::from_message(&result))
}

fn process_aead_seal(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode_secret::<CryptoAeadSealRequest>(request_bytes)?;
    let algorithm = aead_algorithm(&request.algorithm)?;
    let params = AeadParams {
        key: &request.key,
        nonce: &request.nonce,
        aad: &request.aad,
    };
    let ciphertext_with_tag = crypto_dispatch::aead_encrypt(algorithm, &params, &request.plaintext)
        .map_err(map_dispatch_error)?;
    let result = CryptoAeadSealResult {
        algorithm: MessageField::some(aead_identifier(ProtoAead::from(algorithm))),
        ciphertext_with_tag,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(CryptoProtoResult::from_message(&result))
}

fn process_aead_open(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode_secret::<CryptoAeadOpenRequest>(request_bytes)?;
    let algorithm = aead_algorithm(&request.algorithm)?;
    let params = AeadParams {
        key: &request.key,
        nonce: &request.nonce,
        aad: &request.aad,
    };
    let plaintext = crypto_dispatch::aead_decrypt(algorithm, &params, &request.ciphertext_with_tag)
        .map_err(map_dispatch_error)?;
    let result = CryptoAeadOpenResult {
        algorithm: MessageField::some(aead_identifier(ProtoAead::from(algorithm))),
        plaintext: plaintext.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result_from_secret_message(result))
}

fn process_mac_authenticate(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode_secret::<CryptoMacAuthenticateRequest>(request_bytes)?;
    let algorithm = mac_algorithm(&request.algorithm)?;
    let params = MacParams { key: &request.key };
    let tag = crypto_dispatch::mac_authenticate(algorithm, &params, &request.message)
        .map_err(map_dispatch_error)?;
    let result = CryptoMacAuthenticateResult {
        algorithm: MessageField::some(mac_identifier(proto_mac_algorithm(algorithm))),
        tag,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(CryptoProtoResult::from_message(&result))
}

fn process_mac_verify(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode_secret::<CryptoMacVerifyRequest>(request_bytes)?;
    let algorithm = mac_algorithm(&request.algorithm)?;
    let params = MacParams { key: &request.key };
    let verification =
        match crypto_dispatch::mac_verify(algorithm, &params, &request.message, &request.tag) {
            Ok(()) => {
                verification_result(mac_identifier(proto_mac_algorithm(algorithm)), true, None)
            }
            Err(error) if is_verification_mismatch(&error) => {
                verification_result(mac_identifier(proto_mac_algorithm(algorithm)), false, None)
            }
            Err(error) => verification_result(
                mac_identifier(proto_mac_algorithm(algorithm)),
                false,
                Some(map_dispatch_error(error)),
            ),
        };
    Ok(CryptoProtoResult::from_message(&verification))
}

fn process_signature_generate_key_pair(
    request_bytes: &[u8],
) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode::<CryptoSignatureGenerateKeyPairRequest>(request_bytes)?;
    let algorithm = signature_algorithm(&request.algorithm)?;
    let (public_key, secret_key) =
        crypto_dispatch::generate_keypair(algorithm).map_err(map_dispatch_error)?;
    let proto_algorithm = signature_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKeyPair {
        algorithm: MessageField::some(signature_identifier(proto_algorithm)),
        public_key,
        secret_key: secret_key.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result_from_secret_message(result))
}

fn process_signature_sign(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode_secret::<CryptoSignatureSignRequest>(request_bytes)?;
    let algorithm = signature_algorithm(&request.algorithm)?;
    let signature = crypto_dispatch::sign(algorithm, &request.secret_key, &request.message)
        .map_err(map_dispatch_error)?;
    let proto_algorithm = signature_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoSignatureSignResult {
        algorithm: MessageField::some(signature_identifier(proto_algorithm)),
        signature,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(CryptoProtoResult::from_message(&result))
}

fn process_signature_verify(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode::<CryptoSignatureVerifyRequest>(request_bytes)?;
    let algorithm = signature_algorithm(&request.algorithm)?;
    let proto_algorithm = signature_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let verification = match crypto_dispatch::verify(
        algorithm,
        &request.public_key,
        &request.message,
        &request.signature,
    ) {
        Ok(()) => verification_result(signature_identifier(proto_algorithm), true, None),
        Err(error) if is_verification_mismatch(&error) => {
            verification_result(signature_identifier(proto_algorithm), false, None)
        }
        Err(error) => verification_result(
            signature_identifier(proto_algorithm),
            false,
            Some(map_dispatch_error(error)),
        ),
    };
    Ok(CryptoProtoResult::from_message(&verification))
}

fn process_key_agreement_derive_shared_secret(
    request_bytes: &[u8],
) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode_secret::<CryptoKeyAgreementDeriveSharedSecretRequest>(request_bytes)?;
    let algorithm = key_agreement_algorithm(&request.algorithm)?;
    let shared_secret =
        crypto_dispatch::derive_shared_secret(algorithm, &request.secret_key, &request.public_key)
            .map_err(map_dispatch_error)?;
    let proto_algorithm =
        key_agreement_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKeyAgreementDeriveSharedSecretResult {
        algorithm: MessageField::some(key_agreement_identifier(proto_algorithm)),
        shared_secret: shared_secret.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result_from_secret_message(result))
}

fn process_kem_generate_key_pair(
    request_bytes: &[u8],
) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode::<CryptoKemGenerateKeyPairRequest>(request_bytes)?;
    let algorithm = kem_algorithm(&request.algorithm)?;
    let (public_key, secret_key) =
        crypto_dispatch::generate_keypair(algorithm).map_err(map_dispatch_error)?;
    let proto_algorithm = kem_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKeyPair {
        algorithm: MessageField::some(kem_identifier(proto_algorithm)),
        public_key,
        secret_key: secret_key.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result_from_secret_message(result))
}

fn process_kem_encapsulate(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode::<CryptoKemEncapsulateRequest>(request_bytes)?;
    let algorithm = kem_algorithm(&request.algorithm)?;
    let (shared_secret, ciphertext) =
        crypto_dispatch::kem_encapsulate(algorithm, &request.public_key)
            .map_err(map_dispatch_error)?;
    let proto_algorithm = kem_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKemEncapsulation {
        algorithm: MessageField::some(kem_identifier(proto_algorithm)),
        ciphertext,
        shared_secret: shared_secret.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result_from_secret_message(result))
}

fn process_kem_decapsulate(request_bytes: &[u8]) -> Result<CryptoProtoResult, CryptoWireError> {
    let request = decode_secret::<CryptoKemDecapsulateRequest>(request_bytes)?;
    let algorithm = kem_algorithm(&request.algorithm)?;
    let shared_secret =
        crypto_dispatch::kem_decapsulate(algorithm, &request.ciphertext, &request.secret_key)
            .map_err(map_dispatch_error)?;
    let proto_algorithm = kem_algorithm_to_proto(algorithm).ok_or_else(invalid_parameter)?;
    let result = CryptoKemDecapsulateResult {
        algorithm: MessageField::some(kem_identifier(proto_algorithm)),
        shared_secret: shared_secret.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result_from_secret_message(result))
}

fn decode<M>(bytes: &[u8]) -> Result<M, CryptoWireError>
where
    M: Message + Default,
{
    decode_protobuf::<M>(bytes)
}

fn decode_secret<M>(bytes: &[u8]) -> Result<SecretProto<M>, CryptoWireError>
where
    M: Message + Default + ProtoSecretFields,
{
    decode::<M>(bytes).map(SecretProto)
}

fn result_from_secret_message<M>(message: M) -> CryptoProtoResult
where
    M: Message + ProtoSecretFields,
{
    let message = SecretProto(message);
    CryptoProtoResult::from_message(&*message)
}

trait ProtoSecretFields {
    fn zeroize_secret_fields(&mut self);
}

struct SecretProto<M: ProtoSecretFields>(M);

impl<M: ProtoSecretFields> Drop for SecretProto<M> {
    fn drop(&mut self) {
        self.0.zeroize_secret_fields();
    }
}

impl<M: ProtoSecretFields> core::ops::Deref for SecretProto<M> {
    type Target = M;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProtoSecretFields for CryptoAeadSealRequest {
    fn zeroize_secret_fields(&mut self) {
        self.key.zeroize();
        self.plaintext.zeroize();
    }
}

impl ProtoSecretFields for CryptoAeadOpenRequest {
    fn zeroize_secret_fields(&mut self) {
        self.key.zeroize();
    }
}

impl ProtoSecretFields for CryptoAeadOpenResult {
    fn zeroize_secret_fields(&mut self) {
        self.plaintext.zeroize();
    }
}

impl ProtoSecretFields for CryptoMacAuthenticateRequest {
    fn zeroize_secret_fields(&mut self) {
        self.key.zeroize();
    }
}

impl ProtoSecretFields for CryptoMacVerifyRequest {
    fn zeroize_secret_fields(&mut self) {
        self.key.zeroize();
    }
}

impl ProtoSecretFields for CryptoSignatureSignRequest {
    fn zeroize_secret_fields(&mut self) {
        self.secret_key.zeroize();
    }
}

impl ProtoSecretFields for CryptoKeyAgreementDeriveSharedSecretRequest {
    fn zeroize_secret_fields(&mut self) {
        self.secret_key.zeroize();
    }
}

impl ProtoSecretFields for CryptoKeyAgreementDeriveSharedSecretResult {
    fn zeroize_secret_fields(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl ProtoSecretFields for CryptoKemDecapsulateRequest {
    fn zeroize_secret_fields(&mut self) {
        self.secret_key.zeroize();
    }
}

impl ProtoSecretFields for CryptoKemDecapsulateResult {
    fn zeroize_secret_fields(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl ProtoSecretFields for CryptoKemEncapsulation {
    fn zeroize_secret_fields(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl ProtoSecretFields for CryptoKeyPair {
    fn zeroize_secret_fields(&mut self) {
        self.secret_key.zeroize();
    }
}

fn signature_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier>,
) -> Result<Algorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Signature(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| Algorithm::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

fn key_agreement_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier>,
) -> Result<Algorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::KeyAgreement(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| Algorithm::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

fn kem_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier>,
) -> Result<Algorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Kem(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| Algorithm::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

fn aead_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier>,
) -> Result<CoreAead, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Aead(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| CoreAead::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

fn hash_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier>,
) -> Result<CoreHash, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Hash(value) => value
            .as_known()
            .ok_or_else(unsupported_algorithm)
            .and_then(|value| CoreHash::try_from(value).map_err(|_| unsupported_algorithm())),
        _ => Err(invalid_parameter()),
    }
}

fn mac_algorithm(
    identifier: &MessageField<CryptoAlgorithmIdentifier>,
) -> Result<MacAlgorithm, CryptoWireError> {
    match algorithm_branch(identifier)? {
        ProtoAlgorithmBranch::Mac(value) => match value.as_known() {
            Some(ProtoMac::MAC_ALGORITHM_HMAC_SHA256) => Ok(MacAlgorithm::HmacSha256),
            Some(ProtoMac::MAC_ALGORITHM_HMAC_SHA512) => Ok(MacAlgorithm::HmacSha512),
            Some(ProtoMac::MAC_ALGORITHM_UNSPECIFIED) | None => Err(unsupported_algorithm()),
        },
        _ => Err(invalid_parameter()),
    }
}

fn algorithm_branch(
    identifier: &MessageField<CryptoAlgorithmIdentifier>,
) -> Result<&ProtoAlgorithmBranch, CryptoWireError> {
    identifier
        .as_option()
        .and_then(|identifier| identifier.algorithm.as_ref())
        .ok_or_else(invalid_parameter)
}

fn signature_identifier(algorithm: SignatureAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Signature(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn key_agreement_identifier(algorithm: KeyAgreementAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::KeyAgreement(EnumValue::from(
            algorithm,
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn kem_identifier(algorithm: KemAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Kem(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn aead_identifier(algorithm: ProtoAead) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Aead(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn hash_identifier(algorithm: ProtoHash) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Hash(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn mac_identifier(algorithm: ProtoMac) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Mac(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_mac_algorithm(algorithm: MacAlgorithm) -> ProtoMac {
    match algorithm {
        MacAlgorithm::HmacSha256 => ProtoMac::MAC_ALGORITHM_HMAC_SHA256,
        MacAlgorithm::HmacSha512 => ProtoMac::MAC_ALGORITHM_HMAC_SHA512,
    }
}

fn verification_result(
    algorithm: CryptoAlgorithmIdentifier,
    verified: bool,
    error: Option<CryptoWireError>,
) -> CryptoVerificationResult {
    CryptoVerificationResult {
        algorithm: MessageField::some(algorithm),
        status: EnumValue::from(match (verified, error) {
            (true, None) => CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID,
            (false, None) => CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID,
            (false, Some(_)) => CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_ERROR,
            (true, Some(_)) => CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_ERROR,
        }),
        error: match error {
            Some(error) => MessageField::some(error.to_proto()),
            None => MessageField::none(),
        },
        __buffa_unknown_fields: Default::default(),
    }
}

fn map_dispatch_error(error: AlgorithmError) -> CryptoWireError {
    match error {
        AlgorithmError::UnsupportedAlgorithm(_)
        | AlgorithmError::UnsupportedAeadAlgorithm(_)
        | AlgorithmError::UnsupportedHashAlgorithm(_)
        | AlgorithmError::UnsupportedMacAlgorithm(_) => unsupported_algorithm(),
        AlgorithmError::InvalidKey(_) => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        ),
        AlgorithmError::SignatureInvalid(_) => wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
        ),
        AlgorithmError::Crypto(error) => CryptoWireError::from(error),
        _ => wire_error(
            CryptoWireErrorBranch::Backend,
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL,
        ),
    }
}

fn is_verification_mismatch(error: &AlgorithmError) -> bool {
    matches!(
        error,
        AlgorithmError::SignatureInvalid(_)
            | AlgorithmError::Crypto(CryptoError::Signature {
                kind: SignatureFailureKind::InvalidSignature,
                ..
            })
            | AlgorithmError::Crypto(CryptoError::Mac {
                kind: MacFailureKind::VerificationFailed,
                ..
            })
            | AlgorithmError::Crypto(CryptoError::ConstantTimeComparison {
                kind: ConstantTimeFailureKind::NotEqual,
                ..
            })
    )
}

fn invalid_parameter() -> CryptoWireError {
    wire_error(
        CryptoWireErrorBranch::Primitive,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
    )
}

fn unsupported_algorithm() -> CryptoWireError {
    wire_error(
        CryptoWireErrorBranch::Provider,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    )
}

fn wire_error(branch: CryptoWireErrorBranch, reason: CryptoErrorReason) -> CryptoWireError {
    match CryptoWireError::try_new(branch, reason) {
        Ok(error) => error,
        Err(_) => CryptoWireError::malformed_protobuf(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crypto_proto::wire::CryptoProtoStatus;

    #[test]
    fn hash_request_returns_result_envelope() {
        let request = CryptoHashRequest {
            algorithm: MessageField::some(hash_identifier(ProtoHash::HASH_ALGORITHM_SHA2_256)),
            input: b"abc".to_vec(),
            __buffa_unknown_fields: Default::default(),
        };

        let result = process_proto(OP_HASH, &request.encode_to_vec());

        assert_eq!(result.status, CryptoProtoStatus::Result);
        let mut bytes = result.bytes();
        let decoded = CryptoHashResult::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn malformed_request_returns_structured_proto_error() {
        let result = process_proto(OP_HASH, &[0xff, 0xff, 0xff]);

        assert_eq!(result.status, CryptoProtoStatus::CryptoError);
        let error = CryptoWireError::decode(result.bytes()).unwrap();
        assert_eq!(error.branch(), CryptoWireErrorBranch::Backend);
        assert_eq!(
            error.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF
        );
    }

    #[test]
    fn unsupported_proto_algorithm_returns_provider_error() {
        let request = CryptoHashRequest {
            algorithm: MessageField::some(hash_identifier(ProtoHash::HASH_ALGORITHM_UNSPECIFIED)),
            input: b"abc".to_vec(),
            __buffa_unknown_fields: Default::default(),
        };

        let result = process_proto(OP_HASH, &request.encode_to_vec());

        assert_eq!(result.status, CryptoProtoStatus::CryptoError);
        let error = CryptoWireError::decode(result.bytes()).unwrap();
        assert_eq!(error.branch(), CryptoWireErrorBranch::Provider);
        assert_eq!(
            error.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM
        );
    }

    #[test]
    fn invalid_aead_key_length_is_not_authentication_failure() {
        let request = CryptoAeadSealRequest {
            algorithm: MessageField::some(aead_identifier(ProtoAead::AEAD_ALGORITHM_AES_256_GCM)),
            key: vec![0; 31],
            nonce: vec![0; 12],
            aad: Vec::new(),
            plaintext: b"plaintext".to_vec(),
            __buffa_unknown_fields: Default::default(),
        };

        let result = process_proto(OP_AEAD_SEAL, &request.encode_to_vec());

        assert_eq!(result.status, CryptoProtoStatus::CryptoError);
        let error = CryptoWireError::decode(result.bytes()).unwrap();
        assert_eq!(
            error.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY
        );
    }

    #[test]
    fn tampered_aead_ciphertext_is_authentication_failure() {
        let seal = CryptoAeadSealRequest {
            algorithm: MessageField::some(aead_identifier(ProtoAead::AEAD_ALGORITHM_AES_256_GCM)),
            key: vec![0; 32],
            nonce: vec![0; 12],
            aad: b"context".to_vec(),
            plaintext: b"plaintext".to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        let sealed = process_proto(OP_AEAD_SEAL, &seal.encode_to_vec());
        let mut sealed_bytes = sealed.bytes();
        let sealed_result = CryptoAeadSealResult::decode(&mut sealed_bytes).unwrap();
        let mut ciphertext = sealed_result.ciphertext_with_tag;
        let first = ciphertext.first_mut().unwrap();
        *first ^= 0x01;

        let open = CryptoAeadOpenRequest {
            algorithm: MessageField::some(aead_identifier(ProtoAead::AEAD_ALGORITHM_AES_256_GCM)),
            key: vec![0; 32],
            nonce: vec![0; 12],
            aad: b"context".to_vec(),
            ciphertext_with_tag: ciphertext,
            __buffa_unknown_fields: Default::default(),
        };

        let result = process_proto(OP_AEAD_OPEN, &open.encode_to_vec());

        assert_eq!(result.status, CryptoProtoStatus::CryptoError);
        let error = CryptoWireError::decode(result.bytes()).unwrap();
        assert_eq!(
            error.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED
        );
    }

    #[test]
    fn tampered_mac_returns_verification_invalid_not_error() {
        let authenticate = CryptoMacAuthenticateRequest {
            algorithm: MessageField::some(mac_identifier(ProtoMac::MAC_ALGORITHM_HMAC_SHA256)),
            key: vec![0x42; 32],
            message: b"message".to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        let authenticated = process_proto(OP_MAC_AUTHENTICATE, &authenticate.encode_to_vec());
        let mut authenticated_bytes = authenticated.bytes();
        let authenticated_result =
            CryptoMacAuthenticateResult::decode(&mut authenticated_bytes).unwrap();
        let mut tag = authenticated_result.tag;
        let first = tag.first_mut().unwrap();
        *first ^= 0x01;

        let verify = CryptoMacVerifyRequest {
            algorithm: MessageField::some(mac_identifier(ProtoMac::MAC_ALGORITHM_HMAC_SHA256)),
            key: vec![0x42; 32],
            message: b"message".to_vec(),
            tag,
            __buffa_unknown_fields: Default::default(),
        };

        let result = process_proto(OP_MAC_VERIFY, &verify.encode_to_vec());

        assert_eq!(result.status, CryptoProtoStatus::Result);
        let mut bytes = result.bytes();
        let decoded = CryptoVerificationResult::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID)
        );
        assert!(decoded.error.as_option().is_none());
    }

    #[test]
    fn malformed_mac_tag_returns_verification_error() {
        let verify = CryptoMacVerifyRequest {
            algorithm: MessageField::some(mac_identifier(ProtoMac::MAC_ALGORITHM_HMAC_SHA256)),
            key: vec![0x42; 32],
            message: b"message".to_vec(),
            tag: vec![0; 31],
            __buffa_unknown_fields: Default::default(),
        };

        let result = process_proto(OP_MAC_VERIFY, &verify.encode_to_vec());

        assert_eq!(result.status, CryptoProtoStatus::Result);
        let mut bytes = result.bytes();
        let decoded = CryptoVerificationResult::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_ERROR)
        );
        assert!(decoded.error.as_option().is_some());
    }

    #[test]
    fn tampered_signature_returns_verification_invalid_not_error() {
        let algorithm = signature_identifier(SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519);
        let keypair_request = CryptoSignatureGenerateKeyPairRequest {
            algorithm: MessageField::some(algorithm.clone()),
            __buffa_unknown_fields: Default::default(),
        };
        let keypair_result = process_proto(
            OP_SIGNATURE_GENERATE_KEY_PAIR,
            &keypair_request.encode_to_vec(),
        );
        let mut keypair_bytes = keypair_result.bytes();
        let keypair = CryptoKeyPair::decode(&mut keypair_bytes).unwrap();

        let sign = CryptoSignatureSignRequest {
            algorithm: MessageField::some(algorithm.clone()),
            secret_key: keypair.secret_key,
            message: b"message".to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        let signed = process_proto(OP_SIGNATURE_SIGN, &sign.encode_to_vec());
        let mut signed_bytes = signed.bytes();
        let signed_result = CryptoSignatureSignResult::decode(&mut signed_bytes).unwrap();
        let mut signature = signed_result.signature;
        let first = signature.first_mut().unwrap();
        *first ^= 0x01;

        let verify = CryptoSignatureVerifyRequest {
            algorithm: MessageField::some(algorithm),
            public_key: keypair.public_key,
            message: b"message".to_vec(),
            signature,
            __buffa_unknown_fields: Default::default(),
        };

        let result = process_proto(OP_SIGNATURE_VERIFY, &verify.encode_to_vec());

        assert_eq!(result.status, CryptoProtoStatus::Result);
        let mut bytes = result.bytes();
        let decoded = CryptoVerificationResult::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.status.as_known(),
            Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID)
        );
        assert!(decoded.error.as_option().is_none());
    }

    #[test]
    fn reserved_operation_returns_provider_unsupported() {
        let result = process_proto(OP_HPKE_SEAL, &[]);

        assert_eq!(result.status, CryptoProtoStatus::CryptoError);
        let error = CryptoWireError::decode(result.bytes()).unwrap();
        assert_eq!(error.branch(), CryptoWireErrorBranch::Provider);
        assert_eq!(
            error.reason(),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM
        );
    }
}
