// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
