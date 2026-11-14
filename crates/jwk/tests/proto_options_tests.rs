// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "proto")]
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use buffa::Enumeration;
use buffa::Message;
use codec_base64url::bytes_to_base64url;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::public_jwk::Key, CryptoJwkOptions, KeyAlgorithm, PublicJwk, PublicJwks,
};
use envelopes_jwk::proto_options::{ProtectedJwk, ProtectedJwkOptions, ProtectedJwks};
use envelopes_jwk::{AkpJwk, EcJwk, Jwk, Jwks, OkpJwk};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn options_preserve_every_flag_and_exact_optional_utf8_kid() {
    for alg in [false, true] {
        for use_sig in [false, true] {
            for use_enc in [false, true] {
                for kid in [
                    None,
                    Some(Vec::new()),
                    Some("kid/é/e\u{301}\0".as_bytes().to_vec()),
                ] {
                    let wire = CryptoJwkOptions {
                        alg,
                        use_sig,
                        use_enc,
                        kid: kid.map(Into::into),
                    };
                    let owner = ProtectedJwkOptions::try_from(&wire).expect("exact UTF-8 metadata");
                    let returned =
                        CryptoJwkOptions::try_from(owner.as_options()).expect("native options");
                    assert_eq!(
                        (returned.alg, returned.use_sig, returned.use_enc),
                        (alg, use_sig, use_enc)
                    );
                    assert_eq!(returned.kid, wire.kid);
                }
            }
        }
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn options_reject_invalid_utf8_and_unknown_modifiers() -> Result<(), buffa::DecodeError> {
    let mut wire = CryptoJwkOptions {
        alg: false,
        use_sig: false,
        use_enc: false,
        kid: Some(vec![0xff].into()),
    };
    assert_eq!(
        ProtectedJwkOptions::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
    wire.kid = None;
    assert_unknown_wire(&wire, &[0xa0, 0x06, 0x01]);
    Ok(())
}
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_supported_generated_key_preserves_public_variant_fields_and_presence() {
    for identity in KeyAlgorithm::values() {
        let Some(native) = native_key(*identity) else {
            continue;
        };
        for alg in [false, true] {
            for use_present in [false, true] {
                let mut native = clone_public(&native);
                match &mut native {
                    Jwk::Ec(value) => {
                        if !alg {
                            value.alg = None;
                        }
                        if !use_present {
                            value.use_ = None;
                        }
                    }
                    Jwk::Okp(value) => {
                        if !alg {
                            value.alg = None;
                        }
                        if !use_present {
                            value.use_ = None;
                        }
                    }
                    Jwk::Akp(value) => {
                        if !use_present {
                            value.use_ = None;
                        }
                    }
                }
                let wire = PublicJwk::try_from(&native).expect("existing public key identity");
                let owner = ProtectedJwk::try_from(&wire).expect("typed public key");
                assert_eq!(
                    serde_json::to_value(owner.as_jwk()).expect("native fields"),
                    serde_json::to_value(&native).expect("source fields")
                );
                let returned = PublicJwk::try_from(owner.as_jwk()).expect("typed round trip");
                assert_eq!(returned.encode_to_vec(), wire.encode_to_vec());
            }
        }
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn typed_keys_preserve_absent_and_empty_kid() {
    let native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("Ed25519 fixture");
    for kid in [None, Some(String::new()), Some("e\u{301}\0é".to_owned())] {
        let mut native = clone_public(&native);
        if let Jwk::Okp(value) = &mut native {
            value.kid = kid;
        }
        let wire = PublicJwk::try_from(&native).expect("public key");
        let owner = ProtectedJwk::try_from(&wire).expect("typed key");
        assert_eq!(
            serde_json::to_value(owner.as_jwk()).expect("fields"),
            serde_json::to_value(&native).expect("fields")
        );
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn typed_key_rejects_missing_variant_unknown_modifiers_and_wrong_shape(
) -> Result<(), buffa::DecodeError> {
    assert_eq!(
        ProtectedJwk::try_from(&PublicJwk::default()).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("fixture");
    let mut wire = PublicJwk::try_from(&native).expect("wire");
    assert_unknown_wire(&wire, &[0xa0, 0x06, 0x01]);
    wire = PublicJwk::try_from(&native).expect("wire");
    if let Some(Key::Okp(value)) = &mut wire.key {
        value.key_algorithm = KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44.into();
    }
    assert_eq!(
        ProtectedJwk::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    wire = PublicJwk::try_from(&native).expect("wire");
    if let Some(Key::Okp(value)) = &mut wire.key {
        value.kid = Some(vec![0xff].into());
    }
    assert_eq!(
        ProtectedJwk::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
    let child = [0x12, 3, 0xa0, 0x06, 0x01];
    assert_eq!(
        crypto_proto::wire::decode_protobuf::<PublicJwk>(&child),
        Err(crypto_proto::wire::CryptoWireError::malformed_protobuf())
    );
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn typed_keys_reject_unknown_identities_and_malformed_public_members() {
    let native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("fixture");
    for invalid in [0, -1, 999_999, i32::MAX] {
        let mut wire = PublicJwk::try_from(&native).expect("wire");
        if let Some(Key::Okp(value)) = &mut wire.key {
            value.key_algorithm = invalid.into();
        }
        assert_eq!(
            ProtectedJwk::try_from(&wire).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut wire = PublicJwk::try_from(&native).expect("wire");
    if let Some(Key::Okp(value)) = &mut wire.key {
        value.x_base64url.clear();
    }
    assert_eq!(
        ProtectedJwk::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
    if let Some(Key::Okp(value)) = &mut wire.key {
        value.x_base64url = vec![0xff].into();
    }
    assert_eq!(
        ProtectedJwk::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn copied_option_key_and_set_owners_clear_every_owned_string() {
    fn require_cleanup<T: ZeroizeOnDrop>() {}
    require_cleanup::<ProtectedJwkOptions>();
    require_cleanup::<ProtectedJwk>();
    require_cleanup::<ProtectedJwks>();
    let mut options = ProtectedJwkOptions::try_from(&CryptoJwkOptions {
        alg: false,
        use_sig: false,
        use_enc: false,
        kid: Some(b"private-correlator".to_vec().into()),
    })
    .expect("options");
    options.zeroize();
    assert!(options
        .as_options()
        .kid
        .as_ref()
        .is_none_or(String::is_empty));
    let native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("fixture");
    let wire = PublicJwk::try_from(&native).expect("wire");
    let mut owner = ProtectedJwk::try_from(&wire).expect("owner");
    owner.zeroize();
    assert_cleared(owner.as_jwk());
    let set = Jwks::new(vec![native]);
    let wire = PublicJwks::try_from(&set).expect("wire set");
    let mut owner = ProtectedJwks::try_from(&wire).expect("owner set");
    owner.zeroize();
    for key in &owner.as_jwks().keys {
        assert_cleared(key);
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn jwks_partial_failure_and_unknown_modifiers_fail_closed() -> Result<(), buffa::DecodeError> {
    let native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("fixture");
    let wire = PublicJwk::try_from(&native).expect("wire");
    let mut invalid = PublicJwk::try_from(&native).expect("wire");
    if let Some(Key::Okp(value)) = &mut invalid.key {
        value.x_base64url.clear();
    }
    let mut set = PublicJwks {
        keys: vec![wire, invalid].into(),
    };
    assert_eq!(
        ProtectedJwks::try_from(&set).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
    set.keys.clear();
    assert_unknown_wire(&set, &[0xa0, 0x06, 0x01]);
    Ok(())
}
fn clone_public(value: &Jwk) -> Jwk {
    value.clone()
}
fn assert_cleared(value: &Jwk) {
    match value {
        Jwk::Ec(v) => {
            assert!(v.kty.is_empty() && v.crv.is_empty() && v.x.is_empty() && v.y.is_empty());
            assert!(
                v.alg.as_ref().is_none_or(String::is_empty)
                    && v.use_.as_ref().is_none_or(String::is_empty)
                    && v.kid.as_ref().is_none_or(String::is_empty)
            );
        }
        Jwk::Okp(v) => {
            assert!(v.kty.is_empty() && v.crv.is_empty() && v.x.is_empty());
            assert!(
                v.alg.as_ref().is_none_or(String::is_empty)
                    && v.use_.as_ref().is_none_or(String::is_empty)
                    && v.kid.as_ref().is_none_or(String::is_empty)
            );
        }
        Jwk::Akp(v) => {
            assert!(v.kty.is_empty() && v.alg.is_empty() && v.public_key.is_empty());
            assert!(
                v.use_.as_ref().is_none_or(String::is_empty)
                    && v.kid.as_ref().is_none_or(String::is_empty)
            );
        }
    }
}
fn native_key(identity: KeyAlgorithm) -> Option<Jwk> {
    let kid = Some("kid/é/e\u{301}\0".to_owned());
    let ec = |crv: &str, alg: &str, x: &[u8], y: &[u8]| {
        Jwk::Ec(EcJwk {
            kty: "EC".to_owned(),
            crv: crv.to_owned(),
            x: bytes_to_base64url(x),
            y: bytes_to_base64url(y),
            alg: Some(alg.to_owned()),
            use_: Some("sig".to_owned()),
            kid: kid.clone(),
        })
    };
    let okp = |crv: &str, alg: &str, usage: &str, x: &[u8]| {
        Jwk::Okp(OkpJwk {
            kty: "OKP".to_owned(),
            crv: crv.to_owned(),
            x: bytes_to_base64url(x),
            alg: Some(alg.to_owned()),
            use_: Some(usage.to_owned()),
            kid: kid.clone(),
        })
    };
    let akp = |alg: &str, usage: &str, length: usize| {
        Jwk::Akp(AkpJwk {
            kty: "AKP".to_owned(),
            alg: alg.to_owned(),
            public_key: bytes_to_base64url(&vec![0; length]),
            use_: Some(usage.to_owned()),
            kid: kid.clone(),
        })
    };
    match identity {
        KeyAlgorithm::KEY_ALGORITHM_P256 => Some(ec("P-256", "ES256", &P256_X, &P256_Y)),
        KeyAlgorithm::KEY_ALGORITHM_SECP256K1 => Some(ec("secp256k1", "ES256K", &SECP_X, &SECP_Y)),
        KeyAlgorithm::KEY_ALGORITHM_ED25519 => Some(okp("Ed25519", "EdDSA", "sig", &ED_PUBLIC)),
        KeyAlgorithm::KEY_ALGORITHM_X25519 => Some(okp("X25519", "ECDH-ES", "enc", &[9; 32])),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44 => Some(akp("ML-DSA-44", "sig", 1312)),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65 => Some(akp("ML-DSA-65", "sig", 1952)),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87 => Some(akp("ML-DSA-87", "sig", 2592)),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512 => Some(akp("ML-KEM-512", "enc", 800)),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768 => Some(akp("ML-KEM-768", "enc", 1184)),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024 => Some(akp("ML-KEM-1024", "enc", 1568)),
        KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S => Some(akp("SLH-DSA-SHA2-128s", "sig", 32)),
        KeyAlgorithm::KEY_ALGORITHM_X_WING_768 => Some(akp("X-Wing-768", "enc", 1216)),
        KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED
        | KeyAlgorithm::KEY_ALGORITHM_P384
        | KeyAlgorithm::KEY_ALGORITHM_P521 => None,
    }
}
const ED_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const P256_X: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_Y: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];
const SECP_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];
const SECP_Y: [u8; 32] = [
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_public_metadata_rejections_are_not_silently_rewritten() {
    let mut native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("fixture");
    if let Jwk::Okp(value) = &mut native {
        value.alg = Some("unknown".to_owned());
    }
    assert_eq!(
        PublicJwk::try_from(&native).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    if let Jwk::Okp(value) = &mut native {
        value.alg = Some("EdDSA".to_owned());
        value.use_ = Some("enc".to_owned());
    }
    assert_eq!(
        PublicJwk::try_from(&native).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn generated_options_owners_clear_retained_storage() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoJwkOptions>();
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::PublicEcJwk>();
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::PublicOkpJwk>();
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::PublicAkpJwk>();
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::PublicJwk>();
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::PublicJwks>();
    require_cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::PublicJwkDocument>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn typed_optional_metadata_retains_actual_bytes_and_rejects_noncanonical_values() {
    let native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("fixture");
    let mut wire = PublicJwk::try_from(&native).expect("wire");
    if let Some(Key::Okp(value)) = &mut wire.key {
        assert_eq!(value.alg.as_deref(), Some(b"EdDSA".as_slice()));
        assert_eq!(value.usage.as_deref(), Some(b"sig".as_slice()));
        value.alg = None;
        value.usage = None;
    }
    let owner = ProtectedJwk::try_from(&wire).expect("absent metadata remains absent");
    let returned = PublicJwk::try_from(owner.as_jwk()).expect("returned wire");
    if let Some(Key::Okp(value)) = &returned.key {
        assert!(value.alg.is_none());
        assert!(value.usage.is_none());
    }
    for (alg, usage, expected) in [
        (
            Some(Vec::new()),
            None,
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        ),
        (
            Some(b"EdDSA".to_vec()),
            Some(Vec::new()),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        ),
        (
            Some(b"unknown".to_vec()),
            None,
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        ),
        (
            Some(b"EdDSA".to_vec()),
            Some(b"enc".to_vec()),
            CryptoError::PRIMITIVE_INVALID_PARAMETER,
        ),
        (
            Some(vec![0xff]),
            None,
            CryptoError::PRIMITIVE_INVALID_ENCODING,
        ),
        (
            Some(b"EdDSA".to_vec()),
            Some(vec![0xff]),
            CryptoError::PRIMITIVE_INVALID_ENCODING,
        ),
    ] {
        if let Some(Key::Okp(value)) = &mut wire.key {
            value.alg = alg.map(Into::into);
            value.usage = usage.map(Into::into);
        }
        assert_eq!(ProtectedJwk::try_from(&wire).err(), Some(expected));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn retired_draft_boolean_tags_are_not_reinterpreted_as_metadata() {
    let native = native_key(KeyAlgorithm::KEY_ALGORITHM_ED25519).expect("fixture");
    let wire = PublicJwk::try_from(&native).expect("wire");
    let value = wire
        .key
        .as_ref()
        .and_then(|key| match key {
            Key::Okp(value) => Some(value.as_ref()),
            _ => None,
        })
        .expect("OKP fixture");
    assert_unknown_wire(value, &[0x18, 0x01]);
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
