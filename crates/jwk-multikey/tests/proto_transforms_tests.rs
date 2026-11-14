// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]
use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoJwkOptions, CryptoJwkToMultikeyRequest, CryptoJwkToMultikeyResult,
    CryptoMultikeyToJwkRequest, CryptoMultikeyToJwkResult, CryptoPublicKeyToJwkRequest,
    KeyAlgorithm, PublicJwk,
};
use envelopes_jwk::{proto_options::ProtectedJwk, JwkOptions};
use envelopes_jwk_multikey::proto_transforms::{JwkToMultikeyInputs, MultikeyToJwkInputs};
use zeroize::{ZeroizeOnDrop, Zeroizing};
const ED: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
fn native_key() -> envelopes_jwk::Jwk {
    envelopes_jwk::Jwk::Okp(
        envelopes_jwk::ed25519_public_key_to_jwk(
            &ED,
            JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: Some("kid/e\u{301}\0é".to_owned()),
            },
        )
        .expect("native public JWK")
        .into(),
    )
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn multikey_roundtrip_matches_native_codec_names_and_exact_selected_metadata() {
    let native = native_key();
    let expected =
        Zeroizing::new(envelopes_jwk_multikey::jwk_to_multikey(&native).expect("native codec"));
    let wire = CryptoJwkToMultikeyRequest {
        jwk: MessageField::some(PublicJwk::try_from(&native).expect("public model")),
    };
    let result = JwkToMultikeyInputs::try_from(&wire)
        .expect("typed key")
        .multikey()
        .expect("existing transform");
    assert_eq!(result.multikey, expected.as_bytes());
    for alg in [false, true] {
        for use_sig in [false, true] {
            for use_enc in [false, true] {
                for kid in [
                    None,
                    Some(String::new()),
                    Some("kid/e\u{301}\0é".to_owned()),
                ] {
                    let options = || JwkOptions {
                        alg,
                        use_sig,
                        use_enc,
                        kid: kid.clone(),
                    };
                    let expected_jwk = ProtectedJwk::try_from(
                        envelopes_jwk_multikey::multikey_to_jwk(&expected, options())
                            .expect("native decode"),
                    )
                    .expect("native public model");
                    let request = CryptoMultikeyToJwkRequest {
                        multikey: result.multikey.clone(),
                        options: MessageField::some(
                            CryptoJwkOptions::try_from(&options()).expect("options"),
                        ),
                    };
                    let actual = MultikeyToJwkInputs::try_from(&request)
                        .expect("typed request")
                        .jwk_result()
                        .expect("existing decoder");
                    let actual = ProtectedJwk::try_from(actual.jwk.as_option().expect("model"))
                        .expect("public model");
                    assert_eq!(
                        serde_json::to_vec(actual.as_jwk()).expect("actual fields"),
                        serde_json::to_vec(expected_jwk.as_jwk()).expect("native fields")
                    );
                }
            }
        }
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn transforms_reject_missing_unknown_invalid_utf8_and_noncanonical_multibase(
) -> Result<(), buffa::DecodeError> {
    assert_eq!(
        JwkToMultikeyInputs::try_from(&CryptoJwkToMultikeyRequest::default()).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let options = || MessageField::some(CryptoJwkOptions::default());
    let mut request = CryptoMultikeyToJwkRequest {
        multikey: vec![0xff].into(),
        options: options(),
    };
    assert_eq!(
        MultikeyToJwkInputs::try_from(&request).err(),
        Some(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
    request.multikey = b"not-a-canonical-multikey".to_vec().into();
    assert_eq!(
        MultikeyToJwkInputs::try_from(&request)
            .expect("UTF8 request")
            .jwk()
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
    request.options = MessageField::none();
    assert_eq!(
        MultikeyToJwkInputs::try_from(&request).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    request.options = options();
    assert_unknown_wire(&request, &[0xa0, 0x06, 0x01]);
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn existing_multikey_support_does_not_expand_to_slh_or_xwing() {
    for (algorithm, length) in [
        (KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S, 32),
        (KeyAlgorithm::KEY_ALGORITHM_X_WING_768, 1216),
    ] {
        let raw = CryptoPublicKeyToJwkRequest {
            algorithm: algorithm.into(),
            public_key: vec![0; length].into(),
            options: MessageField::some(CryptoJwkOptions::default()),
        };
        let jwk = envelopes_jwk::proto_transforms::PublicKeyToJwkInputs::try_from(&raw)
            .expect("existing raw identity")
            .jwk_result()
            .expect("existing JWK support");
        let request = CryptoJwkToMultikeyRequest {
            jwk: jwk.jwk.clone(),
        };
        assert_eq!(
            JwkToMultikeyInputs::try_from(&request)
                .expect("valid public JWK")
                .multikey()
                .err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn transform_inputs_and_outputs_have_clearing_ownership() {
    fn cleanup<T: ZeroizeOnDrop>() {}
    cleanup::<JwkToMultikeyInputs>();
    cleanup::<MultikeyToJwkInputs>();
    cleanup::<CryptoJwkToMultikeyRequest>();
    cleanup::<CryptoJwkToMultikeyResult>();
    cleanup::<CryptoMultikeyToJwkRequest>();
    cleanup::<CryptoMultikeyToJwkResult>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_existing_multikey_family_matches_native_forward_and_reverse_choices() {
    let cases = vec![
        (KeyAlgorithm::KEY_ALGORITHM_ED25519, ED.to_vec()),
        (KeyAlgorithm::KEY_ALGORITHM_X25519, vec![9; 32]),
        (KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44, vec![0; 1312]),
        (KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65, vec![0; 1952]),
        (KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87, vec![0; 2592]),
        (KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512, vec![0; 800]),
        (KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768, vec![0; 1184]),
        (KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024, vec![0; 1568]),
    ];
    #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
    let cases = {
        let mut cases = cases;
        let mut p256 = vec![3];
        p256.extend_from_slice(&P256_X);
        let mut secp256k1 = vec![2];
        secp256k1.extend_from_slice(&SECP_X);
        cases.push((KeyAlgorithm::KEY_ALGORITHM_P256, p256));
        cases.push((KeyAlgorithm::KEY_ALGORITHM_SECP256K1, secp256k1));
        cases
    };
    for (algorithm, public) in cases {
        let options = || JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: true,
            kid: Some("id/é/e\u{301}\0".to_owned()),
        };
        let raw = CryptoPublicKeyToJwkRequest {
            algorithm: algorithm.into(),
            public_key: public.into(),
            options: MessageField::some(CryptoJwkOptions::try_from(&options()).expect("options")),
        };
        let native = envelopes_jwk::proto_transforms::PublicKeyToJwkInputs::try_from(&raw)
            .expect("raw inputs")
            .jwk()
            .expect("native public key");
        let expected = Zeroizing::new(
            envelopes_jwk_multikey::jwk_to_multikey(native.as_jwk()).expect("existing codec name"),
        );
        let request = CryptoJwkToMultikeyRequest {
            jwk: MessageField::some(PublicJwk::try_from(native.as_jwk()).expect("typed model")),
        };
        let actual = JwkToMultikeyInputs::try_from(&request)
            .expect("inputs")
            .multikey()
            .expect("existing forward transform");
        assert_eq!(actual.multikey, expected.as_bytes());
        let native = ProtectedJwk::try_from(
            envelopes_jwk_multikey::multikey_to_jwk(&expected, options())
                .expect("existing inverse"),
        )
        .expect("native model");
        let inverse = CryptoMultikeyToJwkRequest {
            multikey: actual.multikey.clone(),
            options: MessageField::some(CryptoJwkOptions::try_from(&options()).expect("options")),
        };
        let actual = MultikeyToJwkInputs::try_from(&inverse)
            .expect("inverse inputs")
            .jwk()
            .expect("existing inverse transform");
        assert_eq!(
            serde_json::to_vec(actual.as_jwk()).expect("actual model"),
            serde_json::to_vec(native.as_jwk()).expect("native model")
        );
    }
}

#[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn own_ec_backend_gate_stays_closed_under_dependency_feature_unification() {
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        __buffa::oneof::public_jwk::Key, PublicEcJwk,
    };
    let ec = PublicEcJwk {
        key_algorithm: KeyAlgorithm::KEY_ALGORITHM_P256.into(),
        x_base64url: Vec::new(),
        y_base64url: Vec::new(),
        kid: None,
        alg: None,
        usage: None,
    };
    let request = CryptoJwkToMultikeyRequest {
        jwk: MessageField::some(PublicJwk {
            key: Some(Key::Ec(Box::new(ec))),
        }),
    };
    assert_eq!(
        JwkToMultikeyInputs::try_from(&request).err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
const P256_X: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];

#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
const SECP_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
