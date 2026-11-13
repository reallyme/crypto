// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(feature = "key-identifier-sha1")]

use crypto_core::CryptoError;
use reallyme_crypto::key_identifier::{subject_key_identifier_sha1, SUBJECT_PUBLIC_KEY_MAX_LEN};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn identifiers_match_independent_answers_and_wrong_spans_produce_different_values() {
    let fixture: Value = serde_json::from_str(include_str!("data/key_identifiers.json")).unwrap();
    assert_eq!(fixture["vectors"].as_array().unwrap().len(), 7);
    for v in fixture["vectors"].as_array().unwrap() {
        let bits = hex::decode(v["subject_public_key_bits"].as_str().unwrap()).unwrap();
        let expected = hex::decode(v["identifier"].as_str().unwrap()).unwrap();
        assert_eq!(
            subject_key_identifier_sha1(&bits)
                .unwrap()
                .as_bytes()
                .as_slice(),
            expected
        );
        // SEC1's first byte belongs to the key-bit payload. Removing it is
        // different from removing ASN.1 BIT STRING framing at the boundary.
        assert_ne!(
            subject_key_identifier_sha1(&bits[1..])
                .unwrap()
                .as_bytes()
                .as_slice(),
            expected
        );
        let compressed = hex::decode(v["compressed_key_bits"].as_str().unwrap()).unwrap();
        let compressed_expected =
            hex::decode(v["compressed_identifier"].as_str().unwrap()).unwrap();
        assert_eq!(
            subject_key_identifier_sha1(&compressed)
                .unwrap()
                .as_bytes()
                .as_slice(),
            compressed_expected
        );
        assert_ne!(compressed_expected, expected);
        let mut unused_count_and_bits = vec![0];
        unused_count_and_bits.extend_from_slice(&bits);
        assert_ne!(
            subject_key_identifier_sha1(&unused_count_and_bits)
                .unwrap()
                .as_bytes()
                .as_slice(),
            expected
        );
        let mut tag_length_and_value =
            vec![0x03, u8::try_from(unused_count_and_bits.len()).unwrap()];
        tag_length_and_value.extend_from_slice(&unused_count_and_bits);
        assert_ne!(
            subject_key_identifier_sha1(&tag_length_and_value)
                .unwrap()
                .as_bytes()
                .as_slice(),
            expected
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn identifier_bounds_and_cleanup_are_explicit() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(std::mem::needs_drop::<T>());
    }
    clearing::<reallyme_crypto::key_identifier::SubjectKeyIdentifier>();
    assert!(matches!(
        subject_key_identifier_sha1(&[]),
        Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
    ));
    assert!(subject_key_identifier_sha1(&vec![1; SUBJECT_PUBLIC_KEY_MAX_LEN]).is_ok());
    assert!(matches!(
        subject_key_identifier_sha1(&vec![1; SUBJECT_PUBLIC_KEY_MAX_LEN + 1]),
        Err(CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    ));
    let mut identifier = subject_key_identifier_sha1(b"subject public key value").unwrap();
    identifier.zeroize();
    assert_eq!(identifier.as_bytes(), &[0; 20]);
}
