// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::{EnumValue, Enumeration};
use crypto_hpke::{
    HpkeAeadId, HpkeComponentSupport, HpkeError, HpkeKdfId, HpkeKemId, HpkeSuite,
    HPKE_REGISTERED_AEADS, HPKE_REGISTERED_KDFS, HPKE_REGISTERED_KEMS,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    HpkeAeadId as ProtoAead, HpkeComponentSupport as ProtoSupport, HpkeKdfId as ProtoKdf,
    HpkeKemId as ProtoKem, HpkeSuiteIdentifier,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn component_support_has_total_generated_parity() {
    for value in ProtoSupport::values() {
        let converted = HpkeComponentSupport::try_from(EnumValue::from(*value));
        if value.to_i32() == 0 {
            assert_eq!(converted, Err(HpkeError::PRIMITIVE_INVALID_PARAMETER));
        } else {
            assert_eq!(
                ProtoSupport::from(converted.expect("known support")),
                *value
            );
        }
    }
    for unknown in [i32::MIN, -1, 1, 99, i32::MAX] {
        assert_eq!(
            HpkeComponentSupport::try_from(EnumValue::<ProtoSupport>::from(unknown)),
            Err(HpkeError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_registered_component_matches_the_schema_and_build_relative_support() {
    assert_registry::<ProtoKem, HpkeKemId>(&HPKE_REGISTERED_KEMS);
    assert_registry::<ProtoKdf, HpkeKdfId>(&HPKE_REGISTERED_KDFS);
    assert_registry::<ProtoAead, HpkeAeadId>(&HPKE_REGISTERED_AEADS);
    for value in HPKE_REGISTERED_KEMS {
        assert_eq!(
            crypto_hpke::proto_protocol::kem_capability(value)
                .expect("registered KEM")
                .support
                .as_known(),
            Some(ProtoSupport::from(value.support()))
        );
    }
    for value in HPKE_REGISTERED_KDFS {
        assert_eq!(
            crypto_hpke::proto_protocol::kdf_capability(value)
                .expect("registered KDF")
                .support
                .as_known(),
            Some(ProtoSupport::from(value.support()))
        );
    }
    for value in HPKE_REGISTERED_AEADS {
        assert_eq!(
            crypto_hpke::proto_protocol::aead_capability(value)
                .expect("registered AEAD")
                .support
                .as_known(),
            Some(ProtoSupport::from(value.support()))
        );
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_compound_and_mls_alias_constants_round_trip_exactly() {
    let suites = [
        crypto_hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
        crypto_hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
        crypto_hpke::HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM,
        crypto_hpke::HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM,
        crypto_hpke::HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM,
        crypto_hpke::HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
        crypto_hpke::HPKE_MLKEM512_HKDF_SHA256_AES128GCM,
        crypto_hpke::HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
        crypto_hpke::HPKE_XWING_HKDF_SHA384_AES256GCM,
        crypto_hpke::HPKE_MLKEM768_SHAKE256_AES256GCM,
        crypto_hpke::HPKE_MLKEM768_HKDF_SHA384_AES256GCM,
        crypto_hpke::HPKE_MLKEM1024_SHAKE256_AES256GCM,
        crypto_hpke::HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
        crypto_hpke::HPKE_MLKEM768P256_SHAKE256_AES256GCM,
        crypto_hpke::HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
        crypto_hpke::HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
        crypto_hpke::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        crypto_hpke::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        crypto_hpke::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
        crypto_hpke::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        crypto_hpke::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
    ];
    assert_eq!(suites.len(), 21);
    for suite in suites {
        let wire = HpkeSuiteIdentifier::try_from(suite).expect("registered triple");
        assert_eq!(HpkeSuite::try_from(&wire), Ok(suite));
        assert_eq!(wire.kem.to_i32(), i32::from(suite.kem_id()));
        assert_eq!(wire.kdf.to_i32(), i32::from(suite.kdf_id()));
        assert_eq!(wire.aead.to_i32(), i32::from(suite.aead_id()));
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn protocol_results_and_requests_retain_clearing_ownership() {
    fn cleanup<T: zeroize::ZeroizeOnDrop>() {}
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkePskSenderSetupRequest>(
    );
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkePskSenderSetupResult>(
    );
    cleanup::<
        crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkePskReceiverSetupRequest,
    >();
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkePskReceiverSetupResult>(
    );
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeSenderSealRequest>();
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeSenderSealResult>();
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeReceiverOpenRequest>(
    );
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeReceiverOpenResult>();
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeP256BaseCapabilities>(
    );
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeP256BasePublicKey>();
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeP256BaseSealRequest>(
    );
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeP256BaseOpenRequest>(
    );
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeP256BaseSealedResult>(
    );
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeP256BaseOpenResult>();
    cleanup::<crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeComponentCapability>(
    );
}
fn assert_registry<P, N>(native: &[N])
where
    P: Enumeration + 'static,
    N: TryFrom<u16, Error = HpkeError> + PartialEq + core::fmt::Debug,
{
    assert_eq!(
        P::values().len(),
        native.len().checked_add(1).expect("small registry")
    );
    for value in P::values() {
        if value.to_i32() == 0 {
            continue;
        }
        let number = u16::try_from(value.to_i32()).expect("registered component fits IANA field");
        assert!(native.contains(&N::try_from(number).expect("native component exists")));
    }
}

#[cfg(all(
    feature = "kem-dh-p256",
    feature = "kdf-hkdf-sha256",
    feature = "aead-aes128-gcm"
))]
mod runtime {
    use buffa::{Message, MessageField};
    use crypto_hpke::proto_protocol::{
        HpkePskReceiverSetupInputs, HpkePskSenderSetupInputs, HpkeReceiverOpenInputs,
        HpkeSealInputs, HpkeSenderExportInputs, HpkeSenderSealInputs,
    };
    use crypto_hpke::{
        HpkeError, HpkeReceiverContext, HpkeSenderContext, HpkeSuite,
        HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
    };
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
        CryptoHpkePskReceiverSetupRequest, CryptoHpkePskSenderSetupRequest,
        CryptoHpkePskSenderSetupResult, CryptoHpkeReceiverOpenRequest,
        CryptoHpkeReceiverOpenResult, CryptoHpkeSealRequest, CryptoHpkeSenderExportRequest,
        CryptoHpkeSenderSealRequest, HashAlgorithm, HpkeSuiteIdentifier,
    };
    use zeroize::{Zeroize, ZeroizeOnDrop};
    const INFO: &[u8] = b"info\0\xff";
    const AAD: &[u8] = b"aad\0\xfe";
    const PSK_ID: &[u8] = b"psk-id\0\xfd";
    fn suite() -> HpkeSuite {
        HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM
    }
    fn sender(public: &[u8]) -> CryptoHpkePskSenderSetupRequest {
        CryptoHpkePskSenderSetupRequest {
            suite: MessageField::some(HpkeSuiteIdentifier::try_from(suite()).expect("suite")),
            recipient_public_key: public.to_vec(),
            info: INFO.to_vec(),
            psk: vec![0x11; 32],
            psk_id: PSK_ID.to_vec(),
            __buffa_unknown_fields: Default::default(),
        }
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn exact_setup_content_and_sequence_remain_native_owned() {
        fn send<T: Send>() {}
        fn cleanup<T: ZeroizeOnDrop>() {}
        send::<HpkeSenderContext>();
        send::<HpkeReceiverContext>();
        cleanup::<HpkeSenderContext>();
        cleanup::<HpkeReceiverContext>();
        cleanup::<HpkePskSenderSetupInputs>();
        cleanup::<HpkePskReceiverSetupInputs>();
        cleanup::<HpkeSenderSealInputs>();
        cleanup::<HpkeReceiverOpenInputs>();
        let key = crypto_hpke::derive_keypair(suite(), &[0x42; 32]).expect("recipient");
        let inputs =
            HpkePskSenderSetupInputs::try_from(&sender(&key.public_key)).expect("sender inputs");
        let returned = CryptoHpkePskSenderSetupRequest::try_from(
            &inputs.as_request().expect("native request"),
        )
        .expect("wire request");
        assert_eq!(returned.info, INFO);
        assert_eq!(returned.psk_id, PSK_ID);
        let mut setup = inputs.setup().expect("sender setup");
        let public = CryptoHpkePskSenderSetupResult::from(&setup);
        assert_eq!(public.encapsulated_key, setup.encapsulated_key);
        let receiver_request = CryptoHpkePskReceiverSetupRequest {
            suite: MessageField::some(HpkeSuiteIdentifier::try_from(suite()).expect("suite")),
            encapsulated_key: setup.encapsulated_key.clone(),
            recipient_private_key: key.private_key().to_vec(),
            info: INFO.to_vec(),
            psk: vec![0x11; 32],
            psk_id: PSK_ID.to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        let receiver_inputs =
            HpkePskReceiverSetupInputs::try_from(&receiver_request).expect("receiver inputs");
        let mut receiver = receiver_inputs.setup().expect("receiver setup");
        assert!(
            crypto_hpke::proto_protocol::receiver_setup_public_result(&receiver)
                .encode_to_vec()
                .is_empty()
        );
        for plaintext in [b"first\0\xff".as_slice(), b"second\0\xfe".as_slice()] {
            let wire = CryptoHpkeSenderSealRequest {
                aad: AAD.to_vec(),
                plaintext: plaintext.to_vec(),
                __buffa_unknown_fields: Default::default(),
            };
            let content = HpkeSenderSealInputs::try_from(&wire).expect("sender content");
            let request = content.as_request(&mut setup.context);
            let returned = CryptoHpkeSenderSealRequest::try_from(&request).expect("content wire");
            assert_eq!(returned.aad, AAD);
            assert_eq!(returned.plaintext, plaintext);
            let ciphertext = request.seal().expect("native sender seal");
            assert_eq!(
                crypto_hpke::proto_protocol::sender_seal_public_result(&ciphertext)
                    .expect("public ciphertext result")
                    .ciphertext,
                ciphertext
            );
            let wire = CryptoHpkeReceiverOpenRequest {
                aad: AAD.to_vec(),
                ciphertext,
                __buffa_unknown_fields: Default::default(),
            };
            let content = HpkeReceiverOpenInputs::try_from(&wire).expect("receiver content");
            let opened = content
                .as_request(&mut receiver)
                .open()
                .expect("native receiver open");
            assert_eq!(opened.plaintext.as_slice(), plaintext);
            assert_eq!(
                CryptoHpkeReceiverOpenResult::try_from(&opened)
                    .expect("clearing result")
                    .plaintext,
                plaintext
            );
        }
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn setup_rejects_presence_keys_psk_and_unknown_modifiers() -> Result<(), buffa::DecodeError> {
        let key = crypto_hpke::derive_keypair(suite(), &[0x42; 32]).expect("recipient");
        let mut wire = sender(&key.public_key);
        wire.suite = MessageField::none();
        assert_eq!(
            HpkePskSenderSetupInputs::try_from(&wire).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
        );
        wire = sender(&key.public_key);
        wire.psk.pop();
        assert_eq!(
            HpkePskSenderSetupInputs::try_from(&wire).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
        );
        wire = sender(&key.public_key);
        wire.psk_id.clear();
        assert_eq!(
            HpkePskSenderSetupInputs::try_from(&wire).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
        );
        wire = sender(&key.public_key);
        wire.recipient_public_key.clear();
        assert_eq!(
            HpkePskSenderSetupInputs::try_from(&wire).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PUBLIC_KEY)
        );
        wire = sender(&key.public_key);
        wire.merge_from_slice(&[0xa0, 0x06, 0x01])?;
        assert_eq!(
            HpkePskSenderSetupInputs::try_from(&wire).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
        );
        let mut owner =
            HpkePskSenderSetupInputs::try_from(&sender(&key.public_key)).expect("owner");
        owner.zeroize();
        assert_eq!(
            owner.as_request().err(),
            Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
        );
        Ok(())
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn existing_one_shot_and_export_dtos_preserve_suite_and_binary_context() {
        let key = crypto_hpke::derive_keypair(suite(), &[0x42; 32]).expect("recipient");
        let algorithm = || {
            MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(Algorithm::HpkeSuite(Box::new(
                    HpkeSuiteIdentifier::try_from(suite()).expect("suite"),
                ))),
                __buffa_unknown_fields: Default::default(),
            })
        };
        let wire = CryptoHpkeSealRequest {
            algorithm: algorithm(),
            recipient_public_key: key.public_key.clone(),
            info: INFO.to_vec(),
            aad: AAD.to_vec(),
            plaintext: vec![0, 0xff],
            __buffa_unknown_fields: Default::default(),
        };
        let owner = HpkeSealInputs::try_from(&wire).expect("existing base request");
        let returned = CryptoHpkeSealRequest::try_from(&owner.as_request()).expect("wire parity");
        assert_eq!(returned.encode_to_vec(), wire.encode_to_vec());
        let wire = CryptoHpkeSenderExportRequest {
            algorithm: algorithm(),
            recipient_public_key: key.public_key.clone(),
            info: INFO.to_vec(),
            exporter_context: vec![0, 0xff, 1],
            output_length: 32,
            __buffa_unknown_fields: Default::default(),
        };
        let owner = HpkeSenderExportInputs::try_from(&wire).expect("existing export request");
        let returned =
            CryptoHpkeSenderExportRequest::try_from(&owner.as_request()).expect("export parity");
        assert_eq!(returned.encode_to_vec(), wire.encode_to_vec());
        let wrong = CryptoHpkeSealRequest {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(Algorithm::Hash(
                    HashAlgorithm::HASH_ALGORITHM_SHA2_256.into(),
                )),
                __buffa_unknown_fields: Default::default(),
            }),
            recipient_public_key: key.public_key.clone(),
            info: Vec::new(),
            aad: Vec::new(),
            plaintext: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            HpkeSealInputs::try_from(&wrong).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
        );
    }
}

#[cfg(all(
    feature = "kem-dh-p256",
    feature = "kdf-hkdf-sha256",
    feature = "aead-aes128-gcm"
))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn mismatched_info_psk_identifier_aad_and_tampering_keep_authentication_failure() {
    use buffa::MessageField;
    use crypto_hpke::proto_protocol::{
        HpkePskReceiverSetupInputs, HpkePskSenderSetupInputs, HpkeReceiverOpenInputs,
        HpkeSenderSealInputs,
    };
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        CryptoHpkePskReceiverSetupRequest, CryptoHpkePskSenderSetupRequest,
        CryptoHpkeReceiverOpenRequest, CryptoHpkeSenderSealRequest,
    };
    let suite = crypto_hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM;
    let key = crypto_hpke::derive_keypair(suite, &[0x42; 32]).expect("recipient");
    for (receiver_info, receiver_id, receiver_aad, tamper) in [
        (
            b"wrong-info".as_slice(),
            b"psk\0\xff".as_slice(),
            b"aad\0\xfd".as_slice(),
            false,
        ),
        (
            b"info\0\xfe".as_slice(),
            b"wrong-id".as_slice(),
            b"aad\0\xfd".as_slice(),
            false,
        ),
        (
            b"info\0\xfe".as_slice(),
            b"psk\0\xff".as_slice(),
            b"wrong-aad".as_slice(),
            false,
        ),
        (
            b"info\0\xfe".as_slice(),
            b"psk\0\xff".as_slice(),
            b"aad\0\xfd".as_slice(),
            true,
        ),
    ] {
        let sender_wire = CryptoHpkePskSenderSetupRequest {
            suite: MessageField::some(HpkeSuiteIdentifier::try_from(suite).expect("suite")),
            recipient_public_key: key.public_key.clone(),
            info: b"info\0\xfe".to_vec(),
            psk: vec![0x11; 32],
            psk_id: b"psk\0\xff".to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        let mut sender = HpkePskSenderSetupInputs::try_from(&sender_wire)
            .expect("sender inputs")
            .setup()
            .expect("sender");
        let receiver_wire = CryptoHpkePskReceiverSetupRequest {
            suite: MessageField::some(HpkeSuiteIdentifier::try_from(suite).expect("suite")),
            encapsulated_key: sender.encapsulated_key.clone(),
            recipient_private_key: key.private_key().to_vec(),
            info: receiver_info.to_vec(),
            psk: vec![0x11; 32],
            psk_id: receiver_id.to_vec(),
            __buffa_unknown_fields: Default::default(),
        };
        let mut receiver = HpkePskReceiverSetupInputs::try_from(&receiver_wire)
            .expect("receiver inputs")
            .setup()
            .expect("receiver");
        let content = HpkeSenderSealInputs::try_from(&CryptoHpkeSenderSealRequest {
            aad: b"aad\0\xfd".to_vec(),
            plaintext: b"secret\0\xfc".to_vec(),
            __buffa_unknown_fields: Default::default(),
        })
        .expect("sender content");
        let mut ciphertext = content
            .as_request(&mut sender.context)
            .seal()
            .expect("seal");
        if tamper {
            let byte = ciphertext.first_mut().expect("tag present");
            *byte ^= 1;
        }
        let content = HpkeReceiverOpenInputs::try_from(&CryptoHpkeReceiverOpenRequest {
            aad: receiver_aad.to_vec(),
            ciphertext,
            __buffa_unknown_fields: Default::default(),
        })
        .expect("receiver content");
        assert_eq!(
            content.as_request(&mut receiver).open().err(),
            Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED)
        );
    }
}

#[cfg(feature = "base-p256-aes128gcm")]
mod base {
    use super::HpkeError;
    use crypto_hpke::base_p256::{P256RecipientKey, INFO_MAX_LEN, PUBLIC_KEY_LEN};
    use crypto_hpke::proto_protocol::{
        p256_base_capabilities, P256BaseOpenInputs, P256BaseSealInputs,
    };
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        CryptoHpkeP256BaseOpenRequest, CryptoHpkeP256BaseOpenResult, CryptoHpkeP256BasePublicKey,
        CryptoHpkeP256BaseSealRequest, CryptoHpkeP256BaseSealedResult,
    };
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn fixed_profile_exposes_only_public_key_and_preserves_binary_info() {
        let recipient = P256RecipientKey::import(&[1; 32]).expect("native recipient owner");
        let public = CryptoHpkeP256BasePublicKey::from(&recipient);
        assert_eq!(public.public_key, recipient.public_key());
        let caps = p256_base_capabilities().expect("compiled fixed profile");
        assert!(caps.empty_aad_only);
        assert!(!caps.private_key_exportable);
        assert_eq!(
            caps.public_key_length,
            u32::try_from(PUBLIC_KEY_LEN).expect("fixed bound")
        );
        let wire = CryptoHpkeP256BaseSealRequest {
            recipient_public_key: public.public_key.clone(),
            info: vec![0, 0xff, 0xc3, 0xa9],
            plaintext: vec![0, 0xfe, 1],
            __buffa_unknown_fields: Default::default(),
        };
        let sealed = P256BaseSealInputs::try_from(&wire)
            .expect("fixed content")
            .seal()
            .expect("fixed seal");
        let sealed = CryptoHpkeP256BaseSealedResult::try_from(&sealed).expect("public result");
        let mut open = CryptoHpkeP256BaseOpenRequest {
            encapsulated_key: sealed.encapsulated_key.clone(),
            info: wire.info.clone(),
            ciphertext: sealed.ciphertext.clone(),
            __buffa_unknown_fields: Default::default(),
        };
        let plaintext = P256BaseOpenInputs::try_from(&open)
            .expect("open content")
            .open(&recipient)
            .expect("borrow native owner");
        assert_eq!(plaintext.as_slice(), wire.plaintext);
        assert_eq!(
            CryptoHpkeP256BaseOpenResult::try_from(&plaintext)
                .expect("clearing result")
                .plaintext,
            wire.plaintext
        );
        open.info.push(0);
        assert_eq!(
            P256BaseOpenInputs::try_from(&open)
                .expect("well-formed altered info")
                .open(&recipient)
                .err(),
            Some(HpkeError::PRIMITIVE_AUTHENTICATION_FAILED)
        );
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn fixed_profile_rejects_bounds_and_malformed_input_before_copy() {
        let mut seal = CryptoHpkeP256BaseSealRequest {
            recipient_public_key: vec![0; PUBLIC_KEY_LEN],
            info: Vec::new(),
            plaintext: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            P256BaseSealInputs::try_from(&seal).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PUBLIC_KEY)
        );
        seal.info = vec![0; INFO_MAX_LEN.checked_add(1).expect("bounded info")];
        assert_eq!(
            P256BaseSealInputs::try_from(&seal).err(),
            Some(HpkeError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
        );
        let open = CryptoHpkeP256BaseOpenRequest {
            encapsulated_key: vec![0; PUBLIC_KEY_LEN],
            info: Vec::new(),
            ciphertext: vec![0; 15],
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            P256BaseOpenInputs::try_from(&open).err(),
            Some(HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT)
        );
    }
}

#[cfg(all(
    feature = "kem-dh-p256",
    feature = "kdf-hkdf-sha256",
    feature = "aead-aes128-gcm"
))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn remaining_existing_requests_preserve_every_field_and_reject_unknown_modifiers(
) -> Result<(), buffa::DecodeError> {
    use buffa::{Message, MessageField};
    use crypto_hpke::proto_protocol::{
        HpkeOpenInputs, HpkePskOpenInputs, HpkePskSealInputs, HpkeReceiverExportInputs,
        HpkeSealInputs, HpkeSenderSealInputs,
    };
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
        CryptoHpkeOpenRequest, CryptoHpkePskOpenRequest, CryptoHpkePskSealRequest,
        CryptoHpkeReceiverExportRequest, CryptoHpkeSealRequest, CryptoHpkeSenderSealRequest,
    };
    let suite = crypto_hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM;
    let key = crypto_hpke::derive_keypair(suite, &[0x42; 32]).expect("recipient");
    let algorithm = || {
        MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Algorithm::HpkeSuite(Box::new(
                HpkeSuiteIdentifier::try_from(suite).expect("suite"),
            ))),
            __buffa_unknown_fields: Default::default(),
        })
    };
    let open = CryptoHpkeOpenRequest {
        algorithm: algorithm(),
        recipient_secret_key: key.private_key().to_vec(),
        encapsulated_key: key.public_key.clone(),
        info: vec![0, 0xff],
        aad: vec![0, 0xfe],
        ciphertext: vec![0; 16],
        __buffa_unknown_fields: Default::default(),
    };
    let owner = HpkeOpenInputs::try_from(&open).expect("open inputs");
    assert_eq!(
        CryptoHpkeOpenRequest::try_from(&owner.as_request())
            .expect("open wire")
            .encode_to_vec(),
        open.encode_to_vec()
    );
    let psk_seal = CryptoHpkePskSealRequest {
        algorithm: algorithm(),
        recipient_public_key: key.public_key.clone(),
        info: vec![0, 0xff],
        aad: vec![0, 0xfe],
        plaintext: vec![0, 0xfd],
        psk: vec![0x11; 32],
        psk_id: vec![0, 0xfc],
        __buffa_unknown_fields: Default::default(),
    };
    let owner = HpkePskSealInputs::try_from(&psk_seal).expect("PSK seal inputs");
    assert_eq!(
        CryptoHpkePskSealRequest::try_from(&owner.as_request())
            .expect("PSK seal wire")
            .encode_to_vec(),
        psk_seal.encode_to_vec()
    );
    let psk_open = CryptoHpkePskOpenRequest {
        algorithm: algorithm(),
        recipient_secret_key: key.private_key().to_vec(),
        encapsulated_key: key.public_key.clone(),
        info: vec![0, 0xff],
        aad: vec![0, 0xfe],
        ciphertext: vec![0; 16],
        psk: vec![0x11; 32],
        psk_id: vec![0, 0xfc],
        __buffa_unknown_fields: Default::default(),
    };
    let owner = HpkePskOpenInputs::try_from(&psk_open).expect("PSK open inputs");
    assert_eq!(
        CryptoHpkePskOpenRequest::try_from(&owner.as_request())
            .expect("PSK open wire")
            .encode_to_vec(),
        psk_open.encode_to_vec()
    );
    let export = CryptoHpkeReceiverExportRequest {
        algorithm: algorithm(),
        recipient_secret_key: key.private_key().to_vec(),
        encapsulated_key: key.public_key.clone(),
        info: vec![0, 0xff],
        exporter_context: vec![0, 0xfe],
        output_length: 32,
        __buffa_unknown_fields: Default::default(),
    };
    let owner = HpkeReceiverExportInputs::try_from(&export).expect("receiver export inputs");
    assert_eq!(
        CryptoHpkeReceiverExportRequest::try_from(&owner.as_request())
            .expect("receiver export wire")
            .encode_to_vec(),
        export.encode_to_vec()
    );
    let mut seal = CryptoHpkeSealRequest {
        algorithm: algorithm(),
        recipient_public_key: key.public_key.clone(),
        info: Vec::new(),
        aad: Vec::new(),
        plaintext: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    seal.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        HpkeSealInputs::try_from(&seal).err(),
        Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut content = CryptoHpkeSenderSealRequest {
        aad: Vec::new(),
        plaintext: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    content.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        HpkeSenderSealInputs::try_from(&content).err(),
        Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}

#[cfg(feature = "backend-native")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_request_adapter_has_clearing_ownership() {
    use crypto_hpke::proto_protocol::{
        HpkeOpenInputs, HpkePskOpenInputs, HpkePskReceiverSetupInputs, HpkePskSealInputs,
        HpkePskSenderSetupInputs, HpkeReceiverExportInputs, HpkeReceiverOpenInputs, HpkeSealInputs,
        HpkeSenderExportInputs, HpkeSenderSealInputs,
    };
    fn cleanup<T: zeroize::ZeroizeOnDrop>() {}
    cleanup::<HpkeSealInputs>();
    cleanup::<HpkeOpenInputs>();
    cleanup::<HpkePskSealInputs>();
    cleanup::<HpkePskOpenInputs>();
    cleanup::<HpkeSenderExportInputs>();
    cleanup::<HpkeReceiverExportInputs>();
    cleanup::<HpkePskSenderSetupInputs>();
    cleanup::<HpkePskReceiverSetupInputs>();
    cleanup::<HpkeSenderSealInputs>();
    cleanup::<HpkeReceiverOpenInputs>();
    #[cfg(feature = "base-p256-aes128gcm")]
    {
        cleanup::<crypto_hpke::proto_protocol::P256BaseSealInputs>();
        cleanup::<crypto_hpke::proto_protocol::P256BaseOpenInputs>();
    }
}
