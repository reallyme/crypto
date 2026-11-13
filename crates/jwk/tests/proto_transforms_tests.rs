// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::{Enumeration, Message, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoJwkOptions, CryptoPublicKeyToJcsResult, CryptoPublicKeyToJwkRequest,
    CryptoPublicKeyToJwkResult, KeyAlgorithm,
};
use envelopes_jwk::proto_transforms::PublicKeyToJwkInputs;
use envelopes_jwk::{Jwk, JwkOptions};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[test]
fn every_supported_key_flags_and_kid_match_existing_native_jwk_and_jcs() {
    for algorithm in KeyAlgorithm::values() {
        let Some(public_key) = public_key(*algorithm) else {
            continue;
        };
        for alg in [false, true] {
            for use_sig in [false, true] {
                for use_enc in [false, true] {
                    for kid in [
                        None,
                        Some(String::new()),
                        Some("id/é/e\u{301}\0".to_owned()),
                    ] {
                        let flags = || JwkOptions {
                            alg,
                            use_sig,
                            use_enc,
                            kid: kid.clone(),
                        };
                        let wire = request(*algorithm, &public_key, flags());
                        let owner =
                            PublicKeyToJwkInputs::try_from(&wire).expect("options and identity");
                        match native_jwk(*algorithm, &public_key, flags()) {
                            Ok(expected) => {
                                let actual = owner.jwk().expect("existing native encoder");
                                assert_eq!(
                                    serde_json::to_vec(actual.as_jwk()).expect("native fields"),
                                    serde_json::to_vec(&expected).expect("native fields")
                                );
                                let expected = Zeroizing::new(
                                    native_jcs(*algorithm, &public_key, flags())
                                        .expect("native JCS"),
                                );
                                assert_eq!(
                                    owner.canonical_jcs().expect("protected JCS").canonical_jcs,
                                    expected.as_bytes()
                                );
                                let output = owner.jwk_result().expect("typed result");
                                let output = envelopes_jwk::proto_options::ProtectedJwk::try_from(
                                    output.jwk.as_option().expect("result key"),
                                )
                                .expect("typed key");
                                assert_eq!(
                                    serde_json::to_vec(output.as_jwk()).expect("result fields"),
                                    serde_json::to_vec(actual.as_jwk()).expect("source fields")
                                );
                            }
                            Err(expected) => {
                                assert_eq!(owner.jwk().err(), Some(expected));
                                assert_eq!(owner.canonical_jcs().err(), Some(expected));
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn transforms_reject_unknown_modifiers_missing_options_and_invalid_keys(
) -> Result<(), buffa::DecodeError> {
    let mut wire = request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        &ED_PUBLIC,
        JwkOptions::default(),
    );
    wire.options = MessageField::none();
    assert_eq!(
        PublicKeyToJwkInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    wire = request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        &ED_PUBLIC,
        JwkOptions::default(),
    );
    wire.public_key.clear();
    assert_eq!(
        PublicKeyToJwkInputs::try_from(&wire)
            .expect("known identity")
            .jwk()
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
    wire = request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        &ED_PUBLIC,
        JwkOptions::default(),
    );
    for value in [0, -1, 999_999, i32::MAX] {
        wire.algorithm = value.into();
        assert_eq!(
            PublicKeyToJwkInputs::try_from(&wire).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    wire = request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        &ED_PUBLIC,
        JwkOptions::default(),
    );
    wire.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        PublicKeyToJwkInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut options = CryptoJwkOptions::default();
    options.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    wire = request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        &ED_PUBLIC,
        JwkOptions::default(),
    );
    wire.options = MessageField::some(options);
    assert_eq!(
        PublicKeyToJwkInputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}
#[test]
fn jcs_noncharacter_rejection_remains_typed_and_owners_are_clearing() {
    fn cleanup<T: ZeroizeOnDrop>() {}
    cleanup::<PublicKeyToJwkInputs>();
    cleanup::<CryptoPublicKeyToJwkRequest>();
    cleanup::<CryptoPublicKeyToJwkResult>();
    cleanup::<CryptoPublicKeyToJcsResult>();
    let wire = request(
        KeyAlgorithm::KEY_ALGORITHM_ED25519,
        &ED_PUBLIC,
        JwkOptions {
            kid: Some("\u{fdd0}".to_owned()),
            ..JwkOptions::default()
        },
    );
    assert_eq!(
        PublicKeyToJwkInputs::try_from(&wire)
            .expect("valid UTF8")
            .canonical_jcs()
            .err(),
        Some(CryptoError::PRIMITIVE_INVALID_ENCODING)
    );
}
fn request(
    algorithm: KeyAlgorithm,
    public: &[u8],
    options: JwkOptions,
) -> CryptoPublicKeyToJwkRequest {
    CryptoPublicKeyToJwkRequest {
        algorithm: algorithm.into(),
        public_key: public.to_vec(),
        options: MessageField::some(CryptoJwkOptions::try_from(&options).expect("UTF8 options")),
        __buffa_unknown_fields: Default::default(),
    }
}
fn public_key(algorithm: KeyAlgorithm) -> Option<Vec<u8>> {
    match algorithm {
        KeyAlgorithm::KEY_ALGORITHM_ED25519 => Some(ED_PUBLIC.to_vec()),
        KeyAlgorithm::KEY_ALGORITHM_X25519 => Some(vec![9; 32]),
        KeyAlgorithm::KEY_ALGORITHM_P256 => {
            let mut key = vec![3];
            key.extend_from_slice(&P256_X);
            Some(key)
        }
        KeyAlgorithm::KEY_ALGORITHM_SECP256K1 => {
            let mut key = vec![2];
            key.extend_from_slice(&SECP_X);
            Some(key)
        }
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44 => Some(vec![0; 1312]),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65 => Some(vec![0; 1952]),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87 => Some(vec![0; 2592]),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512 => Some(vec![0; 800]),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768 => Some(vec![0; 1184]),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024 => Some(vec![0; 1568]),
        KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S => Some(vec![0; 32]),
        KeyAlgorithm::KEY_ALGORITHM_X_WING_768 => Some(vec![0; 1216]),
        KeyAlgorithm::KEY_ALGORITHM_UNSPECIFIED
        | KeyAlgorithm::KEY_ALGORITHM_P384
        | KeyAlgorithm::KEY_ALGORITHM_P521 => None,
    }
}
fn native_jwk(
    algorithm: KeyAlgorithm,
    public: &[u8],
    options: JwkOptions,
) -> Result<Jwk, CryptoError> {
    match algorithm {
        KeyAlgorithm::KEY_ALGORITHM_ED25519 => Ok(Jwk::Okp(
            envelopes_jwk::ed25519_public_key_to_jwk(public, options)?.into(),
        )),
        KeyAlgorithm::KEY_ALGORITHM_X25519 => Ok(Jwk::Okp(
            envelopes_jwk::x25519_public_key_to_jwk(public, options)?.into(),
        )),
        KeyAlgorithm::KEY_ALGORITHM_P256 => Ok(Jwk::Ec(envelopes_jwk::p256_public_key_to_jwk(
            public, options,
        )?)),
        KeyAlgorithm::KEY_ALGORITHM_SECP256K1 => Ok(Jwk::Ec(
            envelopes_jwk::secp256k1_public_key_to_jwk(public, options)?,
        )),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44 => Ok(Jwk::Akp(
            envelopes_jwk::mldsa44_public_key_to_jwk(public, options)?,
        )),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65 => Ok(Jwk::Akp(
            envelopes_jwk::mldsa65_public_key_to_jwk(public, options)?,
        )),
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87 => Ok(Jwk::Akp(
            envelopes_jwk::mldsa87_public_key_to_jwk(public, options)?.into(),
        )),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512 => Ok(Jwk::Akp(
            envelopes_jwk::mlkem512_public_key_to_jwk(public, options)?,
        )),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768 => Ok(Jwk::Akp(
            envelopes_jwk::mlkem768_public_key_to_jwk(public, options)?,
        )),
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024 => Ok(Jwk::Akp(
            envelopes_jwk::mlkem1024_public_key_to_jwk(public, options)?.into(),
        )),
        KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S => Ok(Jwk::Akp(
            envelopes_jwk::slh_dsa_sha2_128s_public_key_to_jwk(public, options)?,
        )),
        KeyAlgorithm::KEY_ALGORITHM_X_WING_768 => Ok(Jwk::Akp(
            envelopes_jwk::x_wing_768_public_key_to_jwk(public, options)?,
        )),
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}
fn native_jcs(
    algorithm: KeyAlgorithm,
    public: &[u8],
    options: JwkOptions,
) -> Result<String, CryptoError> {
    match algorithm {
        KeyAlgorithm::KEY_ALGORITHM_ED25519 => {
            envelopes_jwk::ed25519_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_X25519 => {
            envelopes_jwk::x25519_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_P256 => {
            envelopes_jwk::p256_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_SECP256K1 => {
            envelopes_jwk::secp256k1_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44 => {
            envelopes_jwk::mldsa44_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65 => {
            envelopes_jwk::mldsa65_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87 => {
            envelopes_jwk::mldsa87_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512 => {
            envelopes_jwk::mlkem512_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768 => {
            envelopes_jwk::mlkem768_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024 => {
            envelopes_jwk::mlkem1024_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S => {
            envelopes_jwk::slh_dsa_sha2_128s_public_key_to_jwk_jcs(public, options)
        }
        KeyAlgorithm::KEY_ALGORITHM_X_WING_768 => {
            envelopes_jwk::x_wing_768_public_key_to_jwk_jcs(public, options)
        }
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
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
const SECP_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];
