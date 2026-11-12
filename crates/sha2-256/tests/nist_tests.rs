// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
// Embed the pinned public corpus so the identical known answers run in WASM,
// where the test runtime cannot read repository files through std::fs.
#[allow(clippy::large_include_file)]
fn all_inline_byte_aligned_nist_sha256_answers_match() {
    let cases = cases(include_str!(
        "../../../vectors/external/nist-acvp/hash/sha2-256/internalProjection.json"
    ));
    assert_eq!(cases.len(), 512);
    for (message, expected) in cases {
        assert_eq!(
            crypto_sha2_256::digest(&message).as_bytes().as_slice(),
            expected
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn million_byte_message_matches_independent_answer() {
    let message = vec![b'a'; 1_000_000];
    assert_eq!(
        hex::encode(crypto_sha2_256::digest(&message).as_bytes()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

// Only AFT cases with inline byte-aligned messages exercise this one-shot API.
// Monte Carlo and expanded multi-gigabyte cases require different drivers.
fn cases(source: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let file: serde_json::Value = serde_json::from_str(source).unwrap();
    let mut cases = Vec::new();
    for group in file["testGroups"].as_array().unwrap() {
        if group["testType"] != "AFT" {
            continue;
        }
        for case in group["tests"].as_array().unwrap() {
            let bits = case["len"].as_u64().unwrap();
            if !bits.is_multiple_of(8) {
                continue;
            }
            let message = hex::decode(case["msg"].as_str().unwrap()).unwrap();
            assert_eq!(
                u64::try_from(message.len()).unwrap().checked_mul(8),
                Some(bits)
            );
            let expected = hex::decode(case["md"].as_str().unwrap()).unwrap();
            cases.push((message, expected));
        }
    }
    cases
}
