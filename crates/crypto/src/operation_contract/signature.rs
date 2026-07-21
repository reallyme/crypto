// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Signature protobuf execution through semantic operation owners.

use buffa::MessageField;
#[cfg(feature = "secp256k1")]
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoBip340SchnorrSignRequest;
#[cfg(feature = "rsa")]
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoRsaVerifyRequest;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKeyPair, CryptoSignatureDeriveKeyPairRequest, CryptoSignatureGenerateKeyPairRequest,
    CryptoSignatureSignRequest, CryptoSignatureSignResult, CryptoSignatureVerifyRequest,
    CryptoVerificationResult, SignatureAlgorithm,
};
use crypto_proto::wire::CryptoWireError;

use super::operation_error::{
    is_operation_verification_mismatch, map_operation_error, verification_result,
};
#[cfg(all(feature = "dispatch", feature = "rsa"))]
use super::signature_algorithms::rsa_public_key_der_encoding;
use super::signature_algorithms::{
    signature_algorithm, signature_algorithm_value, signature_identifier,
};

#[cfg(feature = "rsa")]
const RSA_SHA1_DIGEST_LEN: usize = 20;
#[cfg(feature = "rsa")]
const RSA_SHA256_DIGEST_LEN: usize = 32;
#[cfg(feature = "rsa")]
const RSA_SHA384_DIGEST_LEN: usize = 48;
#[cfg(feature = "rsa")]
const RSA_SHA512_DIGEST_LEN: usize = 64;

pub(super) fn process_signature_generate_key_pair(
    request: CryptoSignatureGenerateKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoWireError> {
    let proto_algorithm = signature_algorithm_value(&request.algorithm)?;
    let key_pair = if is_bip340(proto_algorithm) {
        crate::operations::signature::generate_bip340_key_pair()
    } else {
        let algorithm = signature_algorithm(&request.algorithm)?;
        crate::operations::signature::generate_key_pair(algorithm)
    }
    .map_err(map_operation_error)?;
    Ok(key_pair_result(
        proto_algorithm,
        key_pair.public_key,
        key_pair.secret_key.to_vec(),
    ))
}

pub(super) fn process_signature_derive_key_pair(
    request: CryptoSignatureDeriveKeyPairRequest,
) -> Result<CryptoKeyPair, CryptoWireError> {
    let proto_algorithm = signature_algorithm_value(&request.algorithm)?;
    let key_pair = if is_bip340(proto_algorithm) {
        crate::operations::signature::derive_bip340_key_pair(&request.secret_key)
    } else {
        let algorithm = signature_algorithm(&request.algorithm)?;
        crate::operations::signature::derive_key_pair(algorithm, &request.secret_key)
    }
    .map_err(map_operation_error)?;
    Ok(key_pair_result(
        proto_algorithm,
        key_pair.public_key,
        key_pair.secret_key.to_vec(),
    ))
}

pub(super) fn process_signature_sign(
    request: CryptoSignatureSignRequest,
) -> Result<CryptoSignatureSignResult, CryptoWireError> {
    let algorithm = signature_algorithm(&request.algorithm)?;
    let proto_algorithm = signature_algorithm_value(&request.algorithm)?;
    let signature =
        crate::operations::signature::sign(algorithm, &request.secret_key, &request.message)
            .map_err(map_operation_error)?;
    let result = CryptoSignatureSignResult {
        algorithm: MessageField::some(signature_identifier(proto_algorithm)),
        signature,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

pub(super) fn process_signature_verify(
    request: CryptoSignatureVerifyRequest,
) -> Result<CryptoVerificationResult, CryptoWireError> {
    let proto_algorithm = signature_algorithm_value(&request.algorithm)?;
    let proto_identifier = signature_identifier(proto_algorithm);
    let verification_outcome = if is_bip340(proto_algorithm) {
        crate::operations::signature::verify_bip340(
            &request.signature,
            &request.message,
            &request.public_key,
        )
    } else {
        let algorithm = signature_algorithm(&request.algorithm)?;
        crate::operations::signature::verify(
            algorithm,
            &request.public_key,
            &request.message,
            &request.signature,
        )
    };
    let verification = match verification_outcome {
        Ok(()) => verification_result(proto_identifier, true, None),
        Err(error) if is_operation_verification_mismatch(&error) => {
            verification_result(proto_identifier, false, None)
        }
        Err(error) => {
            verification_result(proto_identifier, false, Some(map_operation_error(error)))
        }
    };
    Ok(verification)
}

fn is_bip340(algorithm: SignatureAlgorithm) -> bool {
    algorithm == SignatureAlgorithm::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256
}

#[cfg(feature = "secp256k1")]
pub(super) fn process_bip340_schnorr_sign(
    request: CryptoBip340SchnorrSignRequest,
) -> Result<CryptoSignatureSignResult, CryptoWireError> {
    let signature = crate::operations::signature::sign_bip340(
        &request.secret_key,
        &request.message32,
        &request.aux_rand32,
    )
    .map_err(map_operation_error)?;
    let result = CryptoSignatureSignResult {
        algorithm: MessageField::some(signature_identifier(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256,
        )),
        signature,
        __buffa_unknown_fields: Default::default(),
    };
    Ok(result)
}

#[cfg(all(feature = "dispatch", feature = "rsa"))]
pub(super) fn process_rsa_verify(
    request: CryptoRsaVerifyRequest,
) -> Result<CryptoVerificationResult, CryptoWireError> {
    let algorithm = signature_algorithm_value(&request.algorithm)?;
    let proto_identifier = signature_identifier(algorithm);
    let encoding = rsa_public_key_der_encoding(request.public_key_encoding)?;
    let verification_error = match rsa_verification_suite(algorithm)? {
        RsaVerificationSuite::Pkcs1v15 { hash } => {
            crate::operations::signature::verify_rsa_pkcs1v15(
                &request.public_key_der,
                encoding,
                hash,
                &request.message,
                &request.signature,
            )
        }
        RsaVerificationSuite::Pss { params } => crate::operations::signature::verify_rsa_pss(
            &request.public_key_der,
            encoding,
            params,
            &request.message,
            &request.signature,
        ),
    };

    let verification = match verification_error {
        Ok(()) => verification_result(proto_identifier, true, None),
        Err(error) if is_operation_verification_mismatch(&error) => {
            verification_result(proto_identifier, false, None)
        }
        Err(error) => {
            verification_result(proto_identifier, false, Some(map_operation_error(error)))
        }
    };
    Ok(verification)
}

#[cfg(feature = "rsa")]
enum RsaVerificationSuite {
    Pkcs1v15 { hash: crypto_rsa::RsaHash },
    Pss { params: crypto_rsa::RsaPssParams },
}

#[cfg(feature = "rsa")]
fn rsa_verification_suite(
    algorithm: SignatureAlgorithm,
) -> Result<RsaVerificationSuite, CryptoWireError> {
    let suite = match algorithm {
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1 => {
            RsaVerificationSuite::Pkcs1v15 {
                hash: crypto_rsa::RsaHash::Sha1,
            }
        }
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256 => {
            RsaVerificationSuite::Pkcs1v15 {
                hash: crypto_rsa::RsaHash::Sha256,
            }
        }
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384 => {
            RsaVerificationSuite::Pkcs1v15 {
                hash: crypto_rsa::RsaHash::Sha384,
            }
        }
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512 => {
            RsaVerificationSuite::Pkcs1v15 {
                hash: crypto_rsa::RsaHash::Sha512,
            }
        }
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1 => {
            RsaVerificationSuite::Pss {
                params: rsa_pss_params(crypto_rsa::RsaHash::Sha1, RSA_SHA1_DIGEST_LEN),
            }
        }
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256 => {
            RsaVerificationSuite::Pss {
                params: rsa_pss_params(crypto_rsa::RsaHash::Sha256, RSA_SHA256_DIGEST_LEN),
            }
        }
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384 => {
            RsaVerificationSuite::Pss {
                params: rsa_pss_params(crypto_rsa::RsaHash::Sha384, RSA_SHA384_DIGEST_LEN),
            }
        }
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512 => {
            RsaVerificationSuite::Pss {
                params: rsa_pss_params(crypto_rsa::RsaHash::Sha512, RSA_SHA512_DIGEST_LEN),
            }
        }
        _ => return Err(super::wire_error::unsupported_algorithm()),
    };
    Ok(suite)
}

#[cfg(feature = "rsa")]
fn rsa_pss_params(hash: crypto_rsa::RsaHash, salt_len: usize) -> crypto_rsa::RsaPssParams {
    crypto_rsa::RsaPssParams {
        message_hash: hash,
        mgf1_hash: hash,
        salt_len,
    }
}

fn key_pair_result(
    algorithm: crypto_proto::generated::proto::reallyme::crypto::v1::SignatureAlgorithm,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
) -> CryptoKeyPair {
    CryptoKeyPair {
        algorithm: MessageField::some(signature_identifier(algorithm)),
        public_key,
        secret_key,
        __buffa_unknown_fields: Default::default(),
    }
}
