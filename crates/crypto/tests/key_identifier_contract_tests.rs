// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(all(feature = "operation-response", feature = "key-identifier-sha1"))]

use buffa::Message;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoSubjectKeyIdentifierRequest, CryptoSubjectKeyIdentifierResult,
};
use reallyme_crypto::key_identifier::{
    contract, subject_key_identifier_sha1, SUBJECT_PUBLIC_KEY_MAX_LEN,
};
use zeroize::ZeroizeOnDrop;

fn request(bytes: &[u8]) -> CryptoSubjectKeyIdentifierRequest {
    let mut request = CryptoSubjectKeyIdentifierRequest::default();
    assert!(request
        .subject_public_key_bits
        .extend_from_slice(bytes)
        .is_ok());
    request
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_existing_answers_preserve_exact_bit_string_payloads() -> Result<(), CryptoError> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("data/key_identifiers.json")).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        for (source, answer) in [
            ("subject_public_key_bits", "identifier"),
            ("compressed_key_bits", "compressed_identifier"),
        ] {
            let bytes = hex::decode(vector[source].as_str().unwrap()).unwrap();
            let expected = hex::decode(vector[answer].as_str().unwrap()).unwrap();
            assert_eq!(contract::derive(&request(&bytes))?.identifier, expected);
        }
    }
    let exact = [0, 255, 32, 0];
    assert_eq!(request(&exact).encode_to_vec(), [10, 4, 0, 255, 32, 0]);
    assert_eq!(
        contract::derive(&request(&exact))?.identifier,
        subject_key_identifier_sha1(&exact)?.as_bytes()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounds_unknown_modifiers_and_owner_cleanup_are_explicit() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoSubjectKeyIdentifierRequest>();
    clearing::<CryptoSubjectKeyIdentifierResult>();
    assert!(
        matches!(contract::derive(&request(&[])),Err(e) if e==CryptoError::PRIMITIVE_INVALID_LENGTH)
    );
    assert!(contract::derive(&request(&vec![1; SUBJECT_PUBLIC_KEY_MAX_LEN])).is_ok());
    assert!(
        matches!(contract::derive(&request(&vec![1;SUBJECT_PUBLIC_KEY_MAX_LEN+1])),Err(e) if e==CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    );
    use crypto_proto::wire::{decode_protobuf, CryptoWireError};
    assert_eq!(
        decode_protobuf::<CryptoSubjectKeyIdentifierRequest>(&[10, 1, 1, 0xf8, 7, 1]),
        Err(CryptoWireError::malformed_protobuf())
    );
    let mut output = contract::derive(&request(b"identifier input")).unwrap();
    buffa::Message::clear(&mut output);
    assert!(output.identifier.is_empty() || output.identifier.iter().all(|b| *b == 0));
}
