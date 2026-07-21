// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated request execution for the primary operation contract.

#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke",
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
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation, CryptoErrorReason,
    CryptoOperationRequest, CryptoOperationResponse,
};
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke",
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
))]
use crypto_proto::wire::CryptoWireError;
use crypto_proto::wire::CryptoWireErrorBranch;

use super::error::error_response;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
use super::operations::{
    process_kem_decapsulate, process_kem_derive_key_pair, process_kem_encapsulate,
    process_kem_generate_key_pair,
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
use super::operations::{
    process_key_agreement_derive_key_pair, process_key_agreement_derive_shared_secret,
};
use super::request_hpke::{
    process_hpke_derive_key_pair_request, process_hpke_generate_key_pair_request,
    process_hpke_open_request, process_hpke_psk_open_request, process_hpke_psk_seal_request,
    process_hpke_receiver_export_request, process_hpke_seal_request,
    process_hpke_sender_export_request,
};
use super::request_kdf::{
    process_argon2id_derive_request, process_hkdf_derive_request,
    process_jwa_concat_kdf_sha256_derive_request, process_kdf_derive_key_request,
    process_kmac256_derive_request,
};
use super::request_signature::{
    process_bip340_schnorr_sign_request, process_rsa_verify_request,
    process_signature_derive_key_pair_request, process_signature_generate_key_pair_request,
    process_signature_sign_request, process_signature_verify_request,
};
use super::request_symmetric::{
    process_aead_open_request, process_aead_seal_request, process_hash_request,
    process_key_unwrap_request, process_key_wrap_request, process_mac_authenticate_request,
    process_mac_verify_request,
};
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke",
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
))]
use super::response::response_from_result;
use super::wire_error::wire_error;

pub(crate) fn process_operation_request(
    mut request: CryptoOperationRequest,
) -> CryptoOperationResponse {
    let Some(operation) = request.operation.take() else {
        return error_response(wire_error(
            CryptoWireErrorBranch::Primitive,
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MISSING_OPERATION,
        ));
    };

    match operation {
        CryptoOperation::Hash(request) => process_hash_request(*request),
        CryptoOperation::AeadSeal(request) => process_aead_seal_request(*request),
        CryptoOperation::AeadOpen(request) => process_aead_open_request(*request),
        CryptoOperation::MacAuthenticate(request) => process_mac_authenticate_request(*request),
        CryptoOperation::MacVerify(request) => process_mac_verify_request(*request),
        CryptoOperation::SignatureGenerateKeyPair(request) => {
            process_signature_generate_key_pair_request(*request)
        }
        CryptoOperation::SignatureDeriveKeyPair(request) => {
            process_signature_derive_key_pair_request(*request)
        }
        CryptoOperation::SignatureSign(request) => process_signature_sign_request(*request),
        CryptoOperation::SignatureVerify(request) => process_signature_verify_request(*request),
        CryptoOperation::Bip340SchnorrSign(request) => {
            process_bip340_schnorr_sign_request(*request)
        }
        CryptoOperation::RsaVerify(request) => process_rsa_verify_request(*request),
        CryptoOperation::KeyAgreementDeriveSharedSecret(request) => {
            #[cfg(all(
                feature = "dispatch",
                any(
                    feature = "x25519",
                    feature = "p256",
                    feature = "p384",
                    feature = "p521"
                )
            ))]
            {
                process_request(
                    *request,
                    process_key_agreement_derive_shared_secret,
                    CryptoOperationResultBranch::KeyAgreementDeriveSharedSecret,
                )
            }
            #[cfg(not(all(
                feature = "dispatch",
                any(
                    feature = "x25519",
                    feature = "p256",
                    feature = "p384",
                    feature = "p521"
                )
            )))]
            {
                let _ = request;
                unsupported_response()
            }
        }
        CryptoOperation::KeyAgreementDeriveKeyPair(request) => {
            #[cfg(all(
                feature = "dispatch",
                any(
                    feature = "x25519",
                    feature = "p256",
                    feature = "p384",
                    feature = "p521"
                )
            ))]
            {
                process_request(
                    *request,
                    process_key_agreement_derive_key_pair,
                    CryptoOperationResultBranch::KeyAgreementDeriveKeyPair,
                )
            }
            #[cfg(not(all(
                feature = "dispatch",
                any(
                    feature = "x25519",
                    feature = "p256",
                    feature = "p384",
                    feature = "p521"
                )
            )))]
            {
                let _ = request;
                unsupported_response()
            }
        }
        CryptoOperation::KemGenerateKeyPair(request) => {
            #[cfg(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            ))]
            {
                process_request(
                    *request,
                    process_kem_generate_key_pair,
                    CryptoOperationResultBranch::KemGenerateKeyPair,
                )
            }
            #[cfg(not(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            )))]
            {
                let _ = request;
                unsupported_response()
            }
        }
        CryptoOperation::KemDeriveKeyPair(request) => {
            #[cfg(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            ))]
            {
                process_request(
                    *request,
                    process_kem_derive_key_pair,
                    CryptoOperationResultBranch::KemDeriveKeyPair,
                )
            }
            #[cfg(not(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            )))]
            {
                let _ = request;
                unsupported_response()
            }
        }
        CryptoOperation::KemEncapsulate(request) => {
            #[cfg(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            ))]
            {
                process_request(
                    *request,
                    process_kem_encapsulate,
                    CryptoOperationResultBranch::KemEncapsulate,
                )
            }
            #[cfg(not(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            )))]
            {
                let _ = request;
                unsupported_response()
            }
        }
        CryptoOperation::KemDecapsulate(request) => {
            #[cfg(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            ))]
            {
                process_request(
                    *request,
                    process_kem_decapsulate,
                    CryptoOperationResultBranch::KemDecapsulate,
                )
            }
            #[cfg(not(all(
                feature = "dispatch",
                any(
                    feature = "ml-kem-512",
                    feature = "ml-kem-768",
                    feature = "ml-kem-1024",
                    feature = "x-wing"
                )
            )))]
            {
                let _ = request;
                unsupported_response()
            }
        }
        CryptoOperation::Kmac256Derive(request) => process_kmac256_derive_request(*request),
        CryptoOperation::HkdfDerive(request) => process_hkdf_derive_request(*request),
        CryptoOperation::Argon2idDerive(request) => process_argon2id_derive_request(*request),
        CryptoOperation::KdfDeriveKey(request) => process_kdf_derive_key_request(*request),
        CryptoOperation::JwaConcatKdfSha256Derive(request) => {
            process_jwa_concat_kdf_sha256_derive_request(*request)
        }
        CryptoOperation::KeyWrap(request) => process_key_wrap_request(*request),
        CryptoOperation::KeyUnwrap(request) => process_key_unwrap_request(*request),
        CryptoOperation::HpkeSeal(request) => process_hpke_seal_request(*request),
        CryptoOperation::HpkeOpen(request) => process_hpke_open_request(*request),
        CryptoOperation::HpkeGenerateKeyPair(request) => {
            process_hpke_generate_key_pair_request(*request)
        }
        CryptoOperation::HpkeDeriveKeyPair(request) => {
            process_hpke_derive_key_pair_request(*request)
        }
        CryptoOperation::HpkeSenderExport(request) => process_hpke_sender_export_request(*request),
        CryptoOperation::HpkeReceiverExport(request) => {
            process_hpke_receiver_export_request(*request)
        }
        CryptoOperation::HpkePskSeal(request) => process_hpke_psk_seal_request(*request),
        CryptoOperation::HpkePskOpen(request) => process_hpke_psk_open_request(*request),
    }
}

#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke",
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
))]
pub(super) fn process_request<M, R>(
    request: M,
    process: fn(M) -> Result<R, CryptoWireError>,
    wrap: fn(Box<R>) -> CryptoOperationResultBranch,
) -> CryptoOperationResponse {
    response_from_result(process(request), wrap)
}

#[cfg(any(
    not(any(feature = "native", feature = "wasm")),
    not(feature = "sha2"),
    not(feature = "sha3"),
    not(feature = "aes"),
    not(feature = "aes-gcm-siv"),
    not(feature = "chacha20-poly1305"),
    not(feature = "hmac"),
    not(feature = "aes-kw"),
    not(feature = "kmac"),
    not(feature = "hkdf"),
    not(feature = "argon2id"),
    not(feature = "pbkdf2"),
    not(feature = "concat-kdf"),
    not(feature = "hpke"),
    not(feature = "ed25519"),
    not(feature = "p256"),
    not(feature = "p384"),
    not(feature = "p521"),
    not(feature = "rsa"),
    not(feature = "secp256k1"),
    not(feature = "x25519"),
    not(feature = "ml-dsa-44"),
    not(feature = "ml-dsa-65"),
    not(feature = "ml-dsa-87"),
    not(feature = "ml-kem-512"),
    not(feature = "ml-kem-768"),
    not(feature = "ml-kem-1024"),
    not(feature = "slh-dsa"),
    not(feature = "x-wing")
))]
// All-feature builds compile out every feature-disabled branch that calls this
// function. Reduced-feature builds exercise it as the typed fail-closed path.
#[allow(dead_code)]
pub(super) fn unsupported_response() -> CryptoOperationResponse {
    error_response(super::wire_error::unsupported_algorithm())
}
