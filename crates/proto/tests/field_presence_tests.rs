// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compatibility coverage for implicit byte defaults and explicit choices.

#![cfg(feature = "generated")]
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use buffa::Message;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm,
    __buffa::oneof::crypto_operation_request::Operation, CryptoAeadSealRequest,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHashRequest, CryptoHkdfDeriveRequest,
    CryptoHpkeSealRequest, CryptoKmac256DeriveRequest, CryptoSignatureVerifyRequest, HashAlgorithm,
};
use reallyme_crypto_proto::operation_request_wire::{
    decode_operation_request, decode_operation_request_json,
};
use reallyme_crypto_proto::wire::{CryptoWireError, CryptoWireErrorBranch};

#[test]
fn existing_byte_fields_keep_omitted_and_empty_wire_values_equivalent(
) -> Result<(), buffa::DecodeError> {
    // These published fields describe byte strings, not optional protocol
    // attributes. Changing their presence would alter generated APIs and
    // default-value round trips for existing callers.
    assert_empty_byte_defaults::<CryptoHashRequest>(&[0x12, 0])?;
    assert_empty_byte_defaults::<CryptoAeadSealRequest>(&[0x12, 0, 0x1a, 0, 0x22, 0, 0x2a, 0])?;
    assert_empty_byte_defaults::<CryptoSignatureVerifyRequest>(&[0x12, 0, 0x1a, 0, 0x22, 0])?;
    assert_empty_byte_defaults::<CryptoHkdfDeriveRequest>(&[0x12, 0, 0x1a, 0, 0x22, 0])?;
    assert_empty_byte_defaults::<CryptoKmac256DeriveRequest>(&[0x12, 0, 0x1a, 0, 0x22, 0])?;
    assert_empty_byte_defaults::<CryptoHpkeSealRequest>(&[0x12, 0, 0x1a, 0, 0x22, 0, 0x2a, 0])?;
    Ok(())
}

#[test]
fn oneof_preserves_an_explicit_zero_enum_without_a_presence_flag() -> Result<(), buffa::DecodeError>
{
    let absent = CryptoAlgorithmIdentifier::decode_from_slice(&[])?;
    let selected = CryptoAlgorithmIdentifier::decode_from_slice(&[0x30, 0])?;
    assert!(absent.algorithm.is_none());
    assert!(matches!(
        selected.algorithm,
        Some(Algorithm::Hash(value))
            if value.as_known() == Some(HashAlgorithm::HASH_ALGORITHM_UNSPECIFIED)
    ));
    assert_eq!(selected.encode_to_vec(), [0x30, 0]);
    assert_ne!(selected, absent);
    Ok(())
}

#[test]
fn message_and_operation_presence_survive_empty_value_round_trips() -> Result<(), buffa::DecodeError>
{
    let absent = CryptoHashRequest::decode_from_slice(&[])?;
    let present = CryptoHashRequest::decode_from_slice(&[0x0a, 0])?;
    assert!(absent.algorithm.as_option().is_none());
    assert!(present.algorithm.as_option().is_some());
    assert_eq!(present.encode_to_vec(), [0x0a, 0]);
    // MessageField equality compares default values; presence must be queried
    // explicitly and checked on the wire rather than inferred from equality.
    assert!(absent.encode_to_vec().is_empty());

    let absent = decode_operation_request(&[]).expect("absent operation decodes structurally");
    let present = decode_operation_request(&[0x0a, 0]).expect("empty hash branch decodes");
    assert!(absent.operation.is_none());
    assert!(matches!(&present.operation, Some(Operation::Hash(_))));
    assert_eq!(present.encode_to_vec(), [0x0a, 0]);
    assert_ne!(present, absent);
    Ok(())
}

#[test]
fn proto_json_byte_defaults_match_the_existing_binary_contract() {
    let expected = decode_operation_request(&[0x0a, 0]).expect("empty hash branch decodes");
    for json in [
        br#"{"hash":{}}"#.as_slice(),
        br#"{"hash":{"input":""}}"#.as_slice(),
        br#"{"hash":{"input":null}}"#.as_slice(),
    ] {
        let decoded = decode_operation_request_json(json).expect("byte default decodes");
        assert_eq!(decoded, expected);
        assert_eq!(decoded.encode_to_vec(), [0x0a, 0]);
    }
}

#[test]
fn proto_json_preserves_message_and_zero_enum_presence() {
    for (json, binary) in [
        (br#"{"hash":{}}"#.as_slice(), [0x0a, 0].as_slice()),
        (
            br#"{"hash":{"algorithm":{}}}"#.as_slice(),
            [0x0a, 2, 0x0a, 0].as_slice(),
        ),
        (
            br#"{"hash":{"algorithm":{"hash":"HASH_ALGORITHM_UNSPECIFIED"}}}"#.as_slice(),
            [0x0a, 4, 0x0a, 2, 0x30, 0].as_slice(),
        ),
    ] {
        let decoded = decode_operation_request_json(json).expect("presence decodes");
        assert_eq!(decoded.encode_to_vec(), binary);
        assert_eq!(decode_operation_request(binary), Ok(decoded));
    }
}

#[test]
fn unrecognized_presence_flags_fail_with_typed_errors() {
    // A permissive adapter must not silently accept a flag and then ignore its
    // claimed presence. These members have never belonged to the crypto API.
    for name in [
        "hasKid",
        "hasPublicKey",
        "hasSuppPrivInfo",
        "hasExactSignatureAlgorithm",
        "hasSignatureAlgorithm",
        "hasCertificateSha256",
        "hasProtectedKid",
        "hasAttachedPayload",
    ] {
        let json = format!(r#"{{"hash":{{"{name}":true}}}}"#);
        assert_eq!(
            decode_operation_request_json(json.as_bytes()),
            Err(CryptoWireError::try_new(
                CryptoWireErrorBranch::Primitive,
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON,
            )
            .expect("valid fixed error reason")),
        );
    }
}

fn assert_empty_byte_defaults<M>(wire: &[u8]) -> Result<(), buffa::DecodeError>
where
    M: Message + Default + PartialEq + core::fmt::Debug,
{
    let omitted = M::decode_from_slice(&[])?;
    let empty = M::decode_from_slice(wire)?;
    assert_eq!(empty, omitted);
    assert_eq!(empty, M::default());
    assert!(empty.encode_to_vec().is_empty());
    Ok(())
}
