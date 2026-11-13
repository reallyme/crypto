// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(feature = "proto")]

use buffa::Message;
use crypto_proto::error_types::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoShake256ExpandRequest, CryptoShake256ExpandResult,
};
use crypto_sha3::proto::expand_into;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[path = "support/shake_vectors.rs"]
mod vectors;

fn request(input: &[u8], length: u64) -> CryptoShake256ExpandRequest {
    CryptoShake256ExpandRequest {
        input: input.to_vec(),
        output_length: length,
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn vendored_nist_answers_match_borrowed_and_generated_destinations() -> Result<(), CryptoError> {
    for vector in vectors::VECTORS {
        let input = hex::decode(vector.input_hex).unwrap();
        let expected = hex::decode(vector.output_hex).unwrap();
        let request = request(&input, u64::try_from(expected.len()).unwrap());
        let mut borrowed = Zeroizing::new(vec![0xa5; expected.len()]);
        expand_into(&request, &mut borrowed)?;
        assert_eq!(borrowed.as_slice(), expected, "NIST tcId {}", vector.case);
        // The caller chooses this fixture-bounded allocation before passing
        // the final generated clearing owner as the native destination.
        let mut result = CryptoShake256ExpandResult::default();
        result.output.resize(expected.len(), 0);
        expand_into(&request, &mut result.output)?;
        assert_eq!(result.output, expected, "NIST tcId {}", vector.case);
        assert_eq!(request.input, input);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn zero_and_arbitrary_widths_preserve_native_xof_and_binary_input() -> Result<(), CryptoError> {
    let input = [0, 255, 0x80, 0, 32, 255];
    for length in [0usize, 1, 17, 135, 136, 137, 271, 272, 273, 1025] {
        let request = request(&input, u64::try_from(length).unwrap());
        let mut expected = Zeroizing::new(vec![0; length]);
        crypto_sha3::shake256_expand(&input, &mut expected);
        let mut actual = Zeroizing::new(vec![0xa5; length]);
        expand_into(&request, &mut actual)?;
        assert_eq!(actual.as_slice(), expected.as_slice());
        let mut result = CryptoShake256ExpandResult::default();
        result.output.resize(length, 0);
        expand_into(&request, &mut result.output)?;
        assert_eq!(result.output, expected.as_slice());
        assert_eq!(request.input, input);
    }
    let empty = request(&[], 0);
    assert!(empty.encode_to_vec().is_empty());
    let mut result = CryptoShake256ExpandResult::default();
    expand_into(&empty, &mut result.output)?;
    assert!(result.output.is_empty());
    expand_into(&empty, &mut [])?;
    let wire = request(&[0, 255, 32, 0], 257).encode_to_vec();
    assert_eq!(wire, [10, 4, 0, 255, 32, 0, 16, 0x81, 2]);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn mismatched_or_unrepresentable_lengths_never_mutate_borrowed_output() {
    for requested in [0, 1, 63, 65, u64::MAX] {
        let request = request(b"exact input", requested);
        let mut output = Zeroizing::new([0xa5; 64]);
        assert_eq!(
            expand_into(&request, output.as_mut_slice()),
            Err(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
        assert_eq!(*output, [0xa5; 64]);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unknown_modifiers_fail_before_output_mutation() {
    let mut request = request(b"exact\0input\xff", u64::MAX);
    request
        .merge_from_slice(&[0xa2, 0x06, 4, 0, 255, 1, 0])
        .unwrap();
    let mut output = Zeroizing::new([0xa5; 64]);
    assert_eq!(
        expand_into(&request, output.as_mut_slice()),
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    assert_eq!(*output, [0xa5; 64]);
    assert!(!request.__buffa_unknown_fields.is_empty());
    Message::clear(&mut request);
    assert!(request.input.is_empty());
    assert!(request.__buffa_unknown_fields.is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn generated_copies_have_independent_clearing_output_storage() -> Result<(), CryptoError> {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoShake256ExpandRequest>();
    clearing::<CryptoShake256ExpandResult>();
    let request = request(b"owned output", 32);
    let mut original = CryptoShake256ExpandResult::default();
    original.output.resize(32, 0);
    expand_into(&request, &mut original.output)?;
    let expected = Zeroizing::new(original.output.clone());
    let mut retained = original.clone();
    assert_eq!(original.output, retained.output);
    assert_ne!(original.output.as_ptr(), retained.output.as_ptr());
    Message::clear(&mut original);
    assert!(original.output.is_empty());
    assert_eq!(retained.output, expected.as_slice());
    Message::clear(&mut retained);
    assert!(retained.output.is_empty());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn protojson_preserves_exact_uint64_strings_numbers_and_null_default() {
    const INPUT_BASE64: &str = "AP+AAA==";
    let input = [0, 255, 128, 0];
    for length in [4_294_967_296u64, 9_007_199_254_740_993, u64::MAX] {
        for value in [
            serde_json::json!(length.to_string()),
            serde_json::json!(length),
        ] {
            let wire = serde_json::json!({ "input": INPUT_BASE64, "outputLength": value });
            let decoded: CryptoShake256ExpandRequest = serde_json::from_value(wire).unwrap();
            assert_eq!(decoded.input, input);
            assert_eq!(decoded.output_length, length);
            let encoded = serde_json::to_value(&decoded).unwrap();
            assert_eq!(encoded["outputLength"], length.to_string());
            assert_eq!(encoded["input"], INPUT_BASE64);
        }
    }
    let decoded: CryptoShake256ExpandRequest = serde_json::from_value(serde_json::json!({
        "input": INPUT_BASE64,
        "outputLength": null
    }))
    .unwrap();
    assert_eq!(decoded.input, input);
    assert_eq!(decoded.output_length, 0);
    expand_into(&decoded, &mut []).unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn protojson_rejects_negative_and_overflow_lengths_without_disclosing_input() {
    const INPUT_BASE64: &str = "cHJpdmF0ZS1TSEFLRS1pbnB1dA==";
    for invalid in [
        "-1",
        "\"-1\"",
        "\"18446744073709551616\"",
        "18446744073709551616",
    ] {
        let document = format!(r#"{{"input":"{INPUT_BASE64}","outputLength":{invalid}}}"#);
        let error = serde_json::from_str::<CryptoShake256ExpandRequest>(&document)
            .err()
            .unwrap();
        assert_eq!(error.classify(), serde_json::error::Category::Data);
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains(INPUT_BASE64));
        assert!(!diagnostic.contains("private-SHAKE-input"));
    }
}
