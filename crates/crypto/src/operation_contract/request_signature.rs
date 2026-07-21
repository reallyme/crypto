// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Signature branch gates for the primary operation contract.

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ed25519",
        feature = "rsa",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "slh-dsa"
    )
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch;
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoOperationResponse;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoBip340SchnorrSignRequest, CryptoRsaVerifyRequest, CryptoSignatureDeriveKeyPairRequest,
    CryptoSignatureGenerateKeyPairRequest, CryptoSignatureSignRequest,
    CryptoSignatureVerifyRequest,
};

#[cfg(all(
    feature = "dispatch",
    any(
        feature = "rsa",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "slh-dsa"
    )
))]
use super::request::process_request;
#[cfg(all(feature = "dispatch", feature = "secp256k1"))]
use super::signature::process_bip340_schnorr_sign;
#[cfg(all(feature = "dispatch", feature = "rsa"))]
use super::signature::process_rsa_verify;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "rsa",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "slh-dsa"
    )
))]
use super::signature::{
    process_signature_derive_key_pair, process_signature_generate_key_pair, process_signature_sign,
    process_signature_verify,
};

pub(super) fn process_signature_generate_key_pair_request(
    request: CryptoSignatureGenerateKeyPairRequest,
) -> CryptoOperationResponse {
    #[cfg(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    ))]
    {
        process_request(
            request,
            process_signature_generate_key_pair,
            CryptoOperationResultBranch::SignatureGenerateKeyPair,
        )
    }
    #[cfg(not(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_signature_derive_key_pair_request(
    request: CryptoSignatureDeriveKeyPairRequest,
) -> CryptoOperationResponse {
    #[cfg(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    ))]
    {
        process_request(
            request,
            process_signature_derive_key_pair,
            CryptoOperationResultBranch::SignatureDeriveKeyPair,
        )
    }
    #[cfg(not(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_signature_sign_request(
    request: CryptoSignatureSignRequest,
) -> CryptoOperationResponse {
    #[cfg(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    ))]
    {
        process_request(
            request,
            process_signature_sign,
            CryptoOperationResultBranch::SignatureSign,
        )
    }
    #[cfg(not(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_signature_verify_request(
    request: CryptoSignatureVerifyRequest,
) -> CryptoOperationResponse {
    #[cfg(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    ))]
    {
        process_request(
            request,
            process_signature_verify,
            CryptoOperationResultBranch::SignatureVerify,
        )
    }
    #[cfg(not(all(
        feature = "dispatch",
        any(
            feature = "rsa",
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_bip340_schnorr_sign_request(
    request: CryptoBip340SchnorrSignRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "dispatch", feature = "secp256k1"))]
    {
        process_request(
            request,
            process_bip340_schnorr_sign,
            CryptoOperationResultBranch::Bip340SchnorrSign,
        )
    }
    #[cfg(not(all(feature = "dispatch", feature = "secp256k1")))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}

pub(super) fn process_rsa_verify_request(
    request: CryptoRsaVerifyRequest,
) -> CryptoOperationResponse {
    #[cfg(all(feature = "dispatch", feature = "rsa"))]
    {
        process_request(
            request,
            process_rsa_verify,
            CryptoOperationResultBranch::RsaVerify,
        )
    }
    #[cfg(not(all(feature = "dispatch", feature = "rsa")))]
    {
        let _ = request;
        super::request::unsupported_response()
    }
}
