// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema-surface guards for the public operation contract.

const CRYPTO_PROTO: &str = include_str!("../proto/reallyme/crypto/v1/crypto.proto");

const PLATFORM_OPERATION_NAMES: &[&str] = &[
    "platform_key_generate",
    "platform_key_get_public_key",
    "platform_signature_sign",
    "platform_signature_verify",
    "platform_key_agreement_derive_shared_secret",
    "platform_key_delete",
    "platform_key_attest",
];

#[test]
fn provider_owned_platform_operations_remain_outside_the_rust_transport() {
    assert!(!CRYPTO_PROTO.contains("reserved 70 to 76;"));

    for name in PLATFORM_OPERATION_NAMES {
        assert!(!CRYPTO_PROTO.contains(&format!("\"{name}\"")));
        assert!(!CRYPTO_PROTO.contains(&format!(" {name} =")));
    }
}

#[test]
fn opaque_result_envelope_is_absent_from_the_v03_schema() {
    assert!(!CRYPTO_PROTO.contains("CryptoProtoResultEnvelope"));
    assert!(!CRYPTO_PROTO.contains("CryptoProtoResultStatus"));
}

#[test]
fn field_presence_is_never_encoded_as_a_separate_boolean() {
    // Presence belongs to optional fields, messages, or oneofs. A second
    // boolean would let callers express contradictory states across SDKs.
    for declaration in CRYPTO_PROTO.split(';') {
        let tokens = declaration
            .lines()
            .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
            .flat_map(str::split_ascii_whitespace)
            .collect::<Vec<_>>();
        for pair in tokens.windows(2) {
            if pair[0] == "bool" {
                assert!(
                    !pair[1].starts_with("has_"),
                    "{} must use schema-owned presence instead of a flag",
                    pair[1]
                );
            }
        }
    }
}
