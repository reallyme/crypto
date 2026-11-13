// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{decode_signature, reduce, CryptoError};
use serde_json::Value;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[allow(clippy::unwrap_used)]
fn protected_reduction_matches_independent_integer_oracle() {
    // Expected results are computed with Python's arbitrary-precision
    // integer modulo, independently of the curve and bigint engines.
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/data/ed448_rfc8032.json")).unwrap();
    let cases = fixture["scalar_reduction"].as_array().unwrap();
    assert_eq!(cases.len(), 43);
    for case in cases {
        let input = hex::decode(case["input"].as_str().unwrap()).unwrap();
        let expected = hex::decode(case["expected"].as_str().unwrap()).unwrap();
        let scalar = reduce(&input).unwrap();
        assert_eq!(scalar.to_bytes_rfc_8032().as_slice(), expected);
        assert_eq!(
            decode_signature(&expected)
                .unwrap()
                .to_bytes_rfc_8032()
                .as_slice(),
            expected
        );
    }
    assert!(matches!(
        reduce(&[0; 115]),
        Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY)
    ));
}
