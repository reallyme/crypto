// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Strict binary and ProtoJSON tests for the generated operation request boundary.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use std::collections::BTreeSet;

use buffa::Message;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation, CryptoErrorReason,
    CryptoOperationRequest,
};
use reallyme_crypto_proto::operation_request_wire::{
    decode_operation_request, decode_operation_request_json,
};
use reallyme_crypto_proto::wire::{
    CryptoWireError, CryptoWireErrorBranch, MAX_CRYPTO_PROTO_JSON_BYTES,
    MAX_CRYPTO_PROTO_MESSAGE_BYTES,
};

const ALLOWED_JSON_SELECTORS: &[&str] = &[
    "hash",
    "signatureGenerateKeyPair",
    "signatureVerify",
    "rsaVerify",
    "kemGenerateKeyPair",
    "kemEncapsulate",
    "hpkeGenerateKeyPair",
    "hpkeSenderExport",
];

const SECRET_JSON_SELECTORS: &[&str] = &[
    "aeadSeal",
    "aeadOpen",
    "macAuthenticate",
    "macVerify",
    "signatureDeriveKeyPair",
    "signatureSign",
    "bip340SchnorrSign",
    "keyAgreementDeriveSharedSecret",
    "keyAgreementDeriveKeyPair",
    "kemDecapsulate",
    "kemDeriveKeyPair",
    "hkdfDerive",
    "kdfDeriveKey",
    "jwaConcatKdfSha256Derive",
    "kmac256Derive",
    "argon2idDerive",
    "keyWrap",
    "keyUnwrap",
    "hpkeSeal",
    "hpkeOpen",
    "hpkeDeriveKeyPair",
    "hpkeReceiverExport",
    "hpkePskSeal",
    "hpkePskOpen",
];

#[test]
#[allow(clippy::panic)]
fn valid_generated_request_round_trips_through_both_decoders() {
    let request = CryptoOperationRequest {
        operation: Some(CryptoOperation::Hash(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };

    let binary = request.encode_to_vec();
    assert_eq!(decode_operation_request(&binary), Ok(request.clone()));

    let json = match serde_json::to_vec(&request) {
        Ok(json) => json,
        Err(error) => panic!("generated operation request must serialize: {error}"),
    };
    assert_eq!(decode_operation_request_json(&json), Ok(request));
}

#[test]
fn binary_decoder_rejects_unknown_fields() {
    // Field 127, wire type 0, value 1. The operation schema has no such field.
    let unknown_field = [0xF8, 0x07, 0x01];
    assert_eq!(
        decode_operation_request(&unknown_field),
        Err(CryptoWireError::malformed_protobuf())
    );
}

#[test]
fn proto_json_decoder_rejects_unknown_members() {
    assert_primitive_error(
        decode_operation_request_json(br#"{"unknownOperation":{}}"#),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
    );
}

#[test]
fn proto_json_decoder_allows_only_non_secret_operation_selectors() {
    for selector in ALLOWED_JSON_SELECTORS {
        let request = operation_json(selector);
        assert!(
            decode_operation_request_json(request.as_bytes()).is_ok(),
            "non-secret selector {selector} must remain available"
        );
    }
}

#[test]
fn proto_json_decoder_rejects_every_secret_bearing_operation_before_value_decode() {
    for selector in SECRET_JSON_SELECTORS {
        // The intentionally incomplete value proves the discriminant is
        // rejected before serde can parse or unescape any operation fields.
        let request = format!(r#"{{"{selector}":{{"secret":"\u0041""#);
        assert_provider_error(
            decode_operation_request_json(request.as_bytes()),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND,
        );
    }
}

#[test]
#[allow(clippy::panic)]
fn proto_json_policy_classifies_every_operation_selector_in_the_schema() {
    let schema = include_str!("../proto/reallyme/crypto/v1/crypto.proto");
    let request_message = match schema.split_once("message CryptoOperationRequest {") {
        Some((_, request_message)) => request_message,
        None => panic!("CryptoOperationRequest must remain in the canonical schema"),
    };
    let operation_oneof = match request_message.split_once("oneof operation {") {
        Some((_, operation_oneof)) => operation_oneof,
        None => panic!("CryptoOperationRequest.operation must remain a oneof"),
    };
    let operation_fields = match operation_oneof.split_once("\n  }") {
        Some((operation_fields, _)) => operation_fields,
        None => panic!("CryptoOperationRequest.operation must have a closing brace"),
    };

    let schema_selectors = operation_fields
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                return None;
            }
            let mut tokens = line.split_ascii_whitespace();
            let _message_type = tokens.next();
            tokens.next().map(proto_field_name_to_json_selector)
        })
        .collect::<BTreeSet<_>>();

    let expected_selectors = ALLOWED_JSON_SELECTORS
        .iter()
        .chain(SECRET_JSON_SELECTORS)
        .map(|selector| String::from(*selector))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected_selectors.len(),
        ALLOWED_JSON_SELECTORS.len() + SECRET_JSON_SELECTORS.len(),
        "the policy lists must not contain duplicate selectors"
    );
    assert_eq!(schema_selectors, expected_selectors);
}

#[test]
fn proto_json_decoder_rejects_ambiguous_or_escaped_top_level_selectors() {
    assert_primitive_error(
        decode_operation_request_json(br#"{"hash":{},"aeadSeal":{"key":"QQ=="}}"#),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
    );
    assert_primitive_error(
        decode_operation_request_json(br#"{"aead\u0053eal":{}}"#),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
    );
}

#[test]
fn operation_request_decoders_enforce_transport_caps_before_parsing() {
    let oversized_binary = vec![0_u8; MAX_CRYPTO_PROTO_MESSAGE_BYTES + 1];
    assert_primitive_error(
        decode_operation_request(&oversized_binary),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
    );

    let oversized_json = vec![b' '; MAX_CRYPTO_PROTO_JSON_BYTES + 1];
    assert_primitive_error(
        decode_operation_request_json(&oversized_json),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
    );
}

#[allow(clippy::panic)]
fn assert_primitive_error<T>(result: Result<T, CryptoWireError>, reason: CryptoErrorReason) {
    let error = match result {
        Ok(_) => panic!("malformed operation request must fail"),
        Err(error) => error,
    };
    assert_eq!(error.branch(), CryptoWireErrorBranch::Primitive);
    assert_eq!(error.known_reason(), Some(reason));
}

#[allow(clippy::panic)]
fn assert_provider_error<T>(result: Result<T, CryptoWireError>, reason: CryptoErrorReason) {
    let error = match result {
        Ok(_) => panic!("secret-bearing JSON operation must fail"),
        Err(error) => error,
    };
    assert_eq!(error.branch(), CryptoWireErrorBranch::Provider);
    assert_eq!(error.known_reason(), Some(reason));
}

fn operation_json(selector: &str) -> String {
    format!(r#"{{"{selector}":{{}}}}"#)
}

fn proto_field_name_to_json_selector(field_name: &str) -> String {
    let mut selector = String::with_capacity(field_name.len());
    let mut uppercase_next = false;
    for character in field_name.chars() {
        if character == '_' {
            uppercase_next = true;
        } else if uppercase_next {
            selector.extend(character.to_uppercase());
            uppercase_next = false;
        } else {
            selector.push(character);
        }
    }
    selector
}
