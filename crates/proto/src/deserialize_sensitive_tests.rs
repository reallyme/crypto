// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{decode_into, deserialize_bytes, deserialize_optional_bytes};
use crate::error_types::CryptoError;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine,
};
use zeroize::Zeroizing;

#[test]
fn protected_decoding_preserves_each_base64_quantum_boundary() -> Result<(), serde_json::Error> {
    for length in 0..=64 {
        let input = vec![0xfb; length];
        for engine in [&STANDARD, &URL_SAFE] {
            let encoded = engine.encode(&input);
            for spelling in [encoded.as_str(), encoded.trim_end_matches('=')] {
                let json = serde_json::to_string(spelling)?;
                let output = deserialize_bytes(&mut serde_json::Deserializer::from_str(&json))?;
                assert_eq!(output.as_slice(), input.as_slice());
            }
        }
    }
    Ok(())
}

#[test]
#[allow(clippy::expect_used, clippy::panic)]
fn accepted_json_byte_values_match_the_pinned_buffa_helpers() {
    // These are public encoding fixtures, including optional padding,
    // noncanonical trailing bits, both alphabets, and malformed suffixes.
    // The dependency helper is the compatibility oracle, not a second policy.
    for encoded in [
        "",
        "Zg==",
        "Zg=",
        "Zg",
        "Zh==",
        "+/8=",
        "+/8",
        "-_8=",
        "-_8",
        "+_8=",
        "Z",
        "Z===",
        " Zg==",
        "Zg==\n",
        "QUJDREVGSEk=",
        "QUJDREVGSEk%",
        "QUJDREVGSEk=%%%%",
    ] {
        let json = serde_json::to_string(encoded).expect("public fixture serializes");
        let mut protected_input = serde_json::Deserializer::from_str(&json);
        let protected = deserialize_bytes(&mut protected_input);
        let mut upstream_input = serde_json::Deserializer::from_str(&json);
        let upstream = buffa::json_helpers::bytes::deserialize::<Vec<u8>, _>(&mut upstream_input);
        match (protected, upstream) {
            (Ok(protected), Ok(upstream)) => assert_eq!(protected.as_slice(), upstream.as_slice()),
            (Err(_), Err(_)) => {}
            _ => panic!("protobuf byte acceptance changed"),
        }
    }
}

#[test]
#[allow(clippy::panic)]
fn null_and_optional_empty_presence_match_the_existing_contract() -> Result<(), serde_json::Error> {
    let required = deserialize_bytes(&mut serde_json::Deserializer::from_str("null"))?;
    assert!(required.is_empty());
    let absent = deserialize_optional_bytes(&mut serde_json::Deserializer::from_str("null"))?;
    assert!(absent.is_none());
    let present = deserialize_optional_bytes(&mut serde_json::Deserializer::from_str(r#""""#))?;
    assert!(present.as_ref().is_some_and(|bytes| bytes.is_empty()));
    for json in [
        "null",
        r#""""#,
        r#""Zg==""#,
        r#""-_8""#,
        "true",
        "[]",
        "{}",
        "123",
    ] {
        let protected = deserialize_optional_bytes(&mut serde_json::Deserializer::from_str(json));
        let upstream = buffa::json_helpers::opt_bytes::deserialize::<Vec<u8>, _>(
            &mut serde_json::Deserializer::from_str(json),
        );
        match (protected, upstream) {
            (Ok(protected), Ok(upstream)) => assert_eq!(
                protected.as_ref().map(|value| value.as_slice()),
                upstream.as_deref(),
            ),
            (Err(_), Err(_)) => {}
            _ => panic!("optional protobuf byte acceptance changed"),
        }
    }
    Ok(())
}

#[test]
fn malformed_base64_clears_both_alphabet_attempts_in_live_storage() {
    let mut output = Zeroizing::new(vec![0xa5; 64]);
    assert_eq!(
        decode_into("QUJDREVGSEk=%%%%", output.as_mut_slice()),
        Err(CryptoError::PRIMITIVE_INVALID_ENCODING),
    );
    assert!(output.iter().all(|byte| *byte == 0));
    output.fill(0xa5);
    assert_eq!(
        decode_into("QUJDREVG-_8=%%%%", output.as_mut_slice()),
        Err(CryptoError::PRIMITIVE_INVALID_ENCODING),
    );
    assert!(output.iter().all(|byte| *byte == 0));
}

#[test]
fn invalid_base64_and_types_emit_only_fixed_schema_errors() {
    let malformed = deserialize_bytes(&mut serde_json::Deserializer::from_str(r#""QUJDREVG%%%%""#));
    assert!(malformed.is_err());
    assert!(malformed.err().is_some_and(|error| {
        error
            .to_string()
            .contains("CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING")
    }));
    for json in ["true", "123", "123.5", "[]", "{}"] {
        let result = deserialize_bytes(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_err());
        assert!(result.err().is_some_and(|error| {
            error
                .to_string()
                .contains("CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER")
        }));
    }
}

#[test]
fn owned_string_visitors_preserve_byte_values() -> Result<(), serde::de::value::Error> {
    let input = serde::de::value::StringDeserializer::new(String::from("-_8="));
    let output = deserialize_bytes(input)?;
    assert_eq!(output.as_slice(), [0xfb, 0xff]);
    // This deserializer does not supply the optional visitor's visit_some
    // envelope. Preserve upstream rejection while guarding its owned string.
    let input =
        serde::de::value::StringDeserializer::<serde::de::value::Error>::new(String::from("-_8="));
    assert!(deserialize_optional_bytes(input).is_err());
    Ok(())
}
