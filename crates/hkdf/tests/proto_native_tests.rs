// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]

use buffa::{Message, MessageField};
use crypto_core::CryptoError;
use crypto_hkdf::proto_native::HkdfNativeDeriveInputs;
use crypto_hkdf::{derive, HkdfOutput, HkdfSuite};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfDeriveInputs, CryptoHkdfNativeDeriveRequest, CryptoHkdfNativeDeriveResult,
    CryptoHkdfSuiteIdentifier,
};
use hex_literal::hex;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn non_root_output_widths_preserve_all_native_suites() {
    for suite in [
        HkdfSuite::Sha2_256,
        HkdfSuite::Sha2_384,
        HkdfSuite::Sha3_256,
    ] {
        check_native_parity::<1>(suite);
        check_native_parity::<17>(suite);
        check_native_parity::<33>(suite);
        check_native_parity::<65>(suite);
    }
}

fn check_native_parity<const N: usize>(suite: HkdfSuite) {
    let request = request::<N>(suite, &[0, 0xff, 0x80, 1], Some(&[]), &[0, 0xff, 0x20]);
    let inputs = HkdfNativeDeriveInputs::<N>::try_from(&request).expect("valid schema inputs");
    let native = derive::<N>(&inputs.as_request());
    if suite == HkdfSuite::Sha3_256 && !cfg!(feature = "sha3") {
        assert_eq!(
            native.err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
        assert_eq!(
            inputs.derive().err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
        assert_eq!(
            inputs.derive_result().err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
        return;
    }
    let native = native.expect("native derivation");
    let output = inputs.derive().expect("adapted native derivation");
    let result = inputs.derive_result().expect("protected result");
    assert_eq!(output.as_bytes(), native.as_bytes());
    assert_eq!(result.derived_key.as_slice(), native.as_bytes());
    assert_eq!(
        HkdfSuite::try_from(result.suite.as_option().expect("result suite")).expect("known suite"),
        suite
    );
}

// The answers are unchanged from the existing leaf fixtures. HKDF-Expand does
// not encode its output length, so a shorter admitted length is the same prefix.
// RFC 5869 appendix A.1 and A.2: https://www.rfc-editor.org/rfc/rfc5869#appendix-A
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rfc5869_answers_cover_non_root_output_widths() {
    let short = request::<42>(
        HkdfSuite::Sha2_256,
        &[0x0b; 22],
        Some(&hex!("000102030405060708090a0b0c")),
        &hex!("f0f1f2f3f4f5f6f7f8f9"),
    );
    let expected = hex!(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    check_answer::<1>(&short, &expected);
    check_answer::<17>(&short, &expected);
    check_answer::<33>(&short, &expected);
    check_answer::<42>(&short, &expected);
    let long = request::<82>(
        HkdfSuite::Sha2_256,
        &hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f"
        ),
        Some(&hex!(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )),
        &hex!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ),
    );
    let expected = hex!(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );
    check_answer::<65>(&long, &expected);
    check_answer::<82>(&long, &expected);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn sha384_matches_the_existing_independent_leaf_answer() {
    let request = request::<42>(
        HkdfSuite::Sha2_384,
        &[0x0b; 22],
        Some(&hex!("000102030405060708090a0b0c")),
        &hex!("f0f1f2f3f4f5f6f7f8f9"),
    );
    let expected = hex!(
        "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5"
    );
    check_answer::<33>(&request, &expected);
    check_answer::<42>(&request, &expected);
}

#[cfg(feature = "sha3")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn sha3_matches_the_existing_long_input_leaf_fixture() {
    let request = request::<96>(
        HkdfSuite::Sha3_256,
        &[0x0b; 200],
        Some(&[0x0c; 20]),
        &[0x0d; 80],
    );
    let expected = hex!(
        "2f8ac9951b4f0124ff412ca234f8bae921e9bb0dc78d9b56ede2a3b83916b113"
        "28f124c9be81d6bdb5182d59cb1446966b5d620100946481ac2b72561b5f3371"
        "6f5d31d84ec55dddc8b977b61d202dcf6ea1720df79d81b5ab9dbde165802539"
    );
    check_answer::<65>(&request, &expected);
    check_answer::<96>(&request, &expected);
}

fn check_answer<const N: usize>(source: &CryptoHkdfNativeDeriveRequest, expected: &[u8]) {
    let mut request = source.clone();
    request.output_length = u32::try_from(N).expect("fixture width");
    let inputs = HkdfNativeDeriveInputs::<N>::try_from(&request).expect("known-answer inputs");
    assert_eq!(
        inputs.derive().expect("known answer").as_bytes(),
        &expected[..N]
    );
    assert_eq!(
        inputs
            .derive_result()
            .expect("known answer result")
            .derived_key,
        &expected[..N]
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_expansion_bounds_keep_the_existing_backend_error() {
    check_limit::<8160, 8161>(HkdfSuite::Sha2_256);
    check_limit::<12240, 12241>(HkdfSuite::Sha2_384);
    check_limit::<8160, 8161>(HkdfSuite::Sha3_256);
}

fn check_limit<const MAX: usize, const OVER: usize>(suite: HkdfSuite) {
    let accepted = request::<MAX>(suite, &[0x42], None, &[]);
    let inputs = HkdfNativeDeriveInputs::<MAX>::try_from(&accepted).expect("accepted shape");
    let expected = if suite == HkdfSuite::Sha3_256 && !cfg!(feature = "sha3") {
        CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM
    } else {
        assert_eq!(
            inputs.derive().expect("native maximum").as_bytes().len(),
            MAX
        );
        assert_eq!(
            inputs
                .derive_result()
                .expect("result maximum")
                .derived_key
                .len(),
            MAX
        );
        CryptoError::BACKEND_INTERNAL
    };
    let oversized = request::<OVER>(suite, &[0x42], None, &[]);
    let inputs =
        HkdfNativeDeriveInputs::<OVER>::try_from(&oversized).expect("representable native shape");
    assert_eq!(inputs.derive().err(), Some(expected));
    assert_eq!(inputs.derive_result().err(), Some(expected));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn output_binding_and_native_validation_order_are_preserved() {
    let mut wire = request::<17>(HkdfSuite::Sha2_256, &[0x42], None, &[]);
    for invalid in [0, 16, 18, u32::MAX] {
        wire.output_length = invalid;
        assert_eq!(
            HkdfNativeDeriveInputs::<17>::try_from(&wire).err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
    }
    for suite in [
        HkdfSuite::Sha2_256,
        HkdfSuite::Sha2_384,
        HkdfSuite::Sha3_256,
    ] {
        let zero = request::<0>(suite, &[0x42], None, &[]);
        let native = HkdfNativeDeriveInputs::<0>::try_from(&zero).expect("matching zero shape");
        assert_eq!(
            native.derive().err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
        assert_eq!(
            native.derive_result().err(),
            Some(CryptoError::PRIMITIVE_INVALID_LENGTH)
        );
        let empty = request::<0>(suite, &[], None, &[]);
        assert_eq!(
            HkdfNativeDeriveInputs::<0>::try_from(&empty).err(),
            Some(CryptoError::PRIMITIVE_INVALID_KEY)
        );
    }
    let absent = CryptoHkdfNativeDeriveRequest {
        inputs: MessageField::none(),
        output_length: 17,
    };
    assert_eq!(
        HkdfNativeDeriveInputs::<17>::try_from(&absent).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn owners_have_drop_cleanup_and_live_zeroization() {
    fn cleanup<T: ZeroizeOnDrop>() {}
    cleanup::<HkdfNativeDeriveInputs<17>>();
    cleanup::<HkdfOutput<17>>();
    cleanup::<CryptoHkdfNativeDeriveRequest>();
    cleanup::<CryptoHkdfNativeDeriveResult>();
    assert!(core::mem::needs_drop::<HkdfNativeDeriveInputs<17>>());
    assert!(core::mem::needs_drop::<CryptoHkdfNativeDeriveRequest>());
    assert!(core::mem::needs_drop::<CryptoHkdfNativeDeriveResult>());
    let request = request::<17>(HkdfSuite::Sha2_256, &[0x42], Some(&[0, 0xff]), &[0, 0xff]);
    let mut inputs = HkdfNativeDeriveInputs::<17>::try_from(&request).expect("protected inputs");
    let mut result = inputs.derive_result().expect("protected result");
    let mut output = inputs.derive().expect("native output");
    inputs.zeroize();
    assert!(inputs.as_request().ikm.as_bytes().is_empty());
    assert!(inputs.as_request().salt.is_none());
    assert!(inputs.as_request().info.as_bytes().is_empty());
    output.zeroize();
    assert!(output.as_bytes().iter().all(|byte| *byte == 0));
    result.clear();
    assert!(result.derived_key.is_empty());
    assert!(result.suite.as_option().is_none());
}

fn request<const N: usize>(
    suite: HkdfSuite,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> CryptoHkdfNativeDeriveRequest {
    CryptoHkdfNativeDeriveRequest {
        inputs: MessageField::some(CryptoHkdfDeriveInputs {
            suite: MessageField::some(CryptoHkdfSuiteIdentifier::from(suite)),
            input_key_material: ikm.to_vec().into(),
            salt: salt.map(|value| value.to_vec().into()),
            info: info.to_vec().into(),
        }),
        output_length: u32::try_from(N).expect("fixture width"),
    }
}
