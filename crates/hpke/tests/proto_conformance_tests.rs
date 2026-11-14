// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Fill already-clearing message owners.
#![cfg(all(feature = "proto", feature = "test-vectors"))]

use buffa::{Message, MessageField};
use crypto_hpke::{
    proto_conformance, HpkeDerandPskSenderSetupRequest, HpkeDerandSealRequest,
    HpkeDerandSenderExportRequest, HpkeError, HpkePskIdRef, HpkePskRef, HpkeSuite,
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHpkeBaseSealConformanceRequest, CryptoHpkePskSenderSetupConformanceRequest,
    CryptoHpkeSenderExportConformanceRequest, HpkeSuiteIdentifier,
};
use crypto_proto::wire::{decode_protobuf, CryptoWireError};
use zeroize::ZeroizeOnDrop;

fn suite() -> HpkeSuite {
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("data/base_p256.json")).unwrap()
}
fn hex_field(value: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(value[name].as_str().unwrap()).unwrap()
}
fn seal_request() -> CryptoHpkeBaseSealConformanceRequest {
    let value = fixture();
    let mut request = CryptoHpkeBaseSealConformanceRequest::default();
    request.suite = MessageField::some(HpkeSuiteIdentifier::try_from(suite()).unwrap());
    request.recipient_public_key = hex_field(&value, "pkRm").into();
    request.encapsulation_randomness = hex_field(&value, "ikmE").into();
    request.info = hex_field(&value, "info").into();
    request.aad = hex_field(&value["encryption"], "aad").into();
    request.plaintext = hex_field(&value["encryption"], "pt").into();
    request
}
fn export_request() -> CryptoHpkeSenderExportConformanceRequest {
    let seal = seal_request();
    let mut output = CryptoHpkeSenderExportConformanceRequest::default();
    output.suite = MessageField::some(HpkeSuiteIdentifier::try_from(suite()).unwrap());
    assert!(output
        .recipient_public_key
        .extend_from_slice(&seal.recipient_public_key)
        .is_ok());
    assert!(output
        .encapsulation_randomness
        .extend_from_slice(&seal.encapsulation_randomness)
        .is_ok());
    assert!(output.info.extend_from_slice(&seal.info).is_ok());
    assert!(output
        .exporter_context
        .extend_from_slice(&[0, 255, 32, 0])
        .is_ok());
    output.output_length = 32;
    output
}
fn psk_request() -> CryptoHpkePskSenderSetupConformanceRequest {
    let seal = seal_request();
    let mut output = CryptoHpkePskSenderSetupConformanceRequest::default();
    output.suite = MessageField::some(HpkeSuiteIdentifier::try_from(suite()).unwrap());
    assert!(output
        .recipient_public_key
        .extend_from_slice(&seal.recipient_public_key)
        .is_ok());
    assert!(output
        .encapsulation_randomness
        .extend_from_slice(&seal.encapsulation_randomness)
        .is_ok());
    assert!(output.info.extend_from_slice(&[0, 255, 32, 0]).is_ok());
    assert!(output.psk.extend_from_slice(&[0x2a; 32]).is_ok());
    assert!(output.psk_id.extend_from_slice(&[0, 255, 32, 0]).is_ok());
    output
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn borrowed_native_requests_preserve_pointers_presence_and_binary_context() -> Result<(), HpkeError>
{
    let seal = seal_request();
    let native = HpkeDerandSealRequest::try_from(&seal)?;
    assert_eq!(
        native.recipient_public_key.as_ptr(),
        seal.recipient_public_key.as_ptr()
    );
    assert_eq!(
        native.encapsulation_randomness.as_ptr(),
        seal.encapsulation_randomness.as_ptr()
    );
    assert_eq!(native.info.as_ptr(), seal.info.as_ptr());
    assert_eq!(native.aad.as_ptr(), seal.aad.as_ptr());
    assert_eq!(native.plaintext.as_ptr(), seal.plaintext.as_ptr());
    let export = export_request();
    let native = HpkeDerandSenderExportRequest::try_from(&export)?;
    assert_eq!(native.exporter_context, &[0, 255, 32, 0]);
    assert_eq!(
        native.exporter_context.as_ptr(),
        export.exporter_context.as_ptr()
    );
    assert_eq!(native.output_length, 32);
    let psk = psk_request();
    let native = HpkeDerandPskSenderSetupRequest::try_from(&psk)?;
    assert_eq!(native.psk.as_slice().as_ptr(), psk.psk.as_ptr());
    assert_eq!(native.psk_id.as_slice().as_ptr(), psk.psk_id.as_ptr());
    assert_eq!(native.info.as_ptr(), psk.info.as_ptr());
    assert!(
        matches!(HpkeDerandSealRequest::try_from(&CryptoHpkeBaseSealConformanceRequest::default()),Err(e)if e==HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    let wire = CryptoHpkeBaseSealConformanceRequest {
        suite: MessageField::some(HpkeSuiteIdentifier::try_from(suite())?),
        recipient_public_key: Vec::new().into(),
        encapsulation_randomness: Vec::new().into(),
        info: vec![0, 255, 32, 0].into(),
        aad: Vec::new().into(),
        plaintext: Vec::new().into(),
    };
    assert_eq!(
        wire.encode_to_vec(),
        [10, 6, 8, 16, 16, 1, 24, 1, 34, 4, 0, 255, 32, 0]
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn deterministic_base_seal_matches_rfc9180_and_native_boundary() -> Result<(), HpkeError> {
    let request = seal_request();
    let native = HpkeDerandSealRequest::try_from(&request)?;
    let expected = crypto_hpke::seal_base_derand(&native)?;
    let actual = proto_conformance::seal_base(&request)?;
    let vector = fixture();
    assert_eq!(actual.encapsulated_key, hex_field(&vector, "enc"));
    assert_eq!(actual.ciphertext, hex_field(&vector["encryption"], "ct"));
    assert_eq!(actual.encapsulated_key, expected.encapsulated_key);
    assert_eq!(actual.ciphertext, expected.ciphertext);
    let repeated = proto_conformance::seal_base(&request)?;
    assert_eq!(repeated.ciphertext, actual.ciphertext);
    let mut empty = seal_request();
    empty.aad.clear();
    assert_eq!(
        proto_conformance::seal_base(&empty)?.ciphertext,
        hex_field(&vector, "empty_aad_ciphertext")
    );
    let mut binary = seal_request();
    binary.info = vec![0, 255, 32, 0].into();
    binary.aad = vec![255, 0].into();
    binary.plaintext.clear();
    let expected = crypto_hpke::seal_base_derand(&HpkeDerandSealRequest::try_from(&binary)?)?;
    assert_eq!(
        proto_conformance::seal_base(&binary)?.ciphertext,
        expected.ciphertext
    );
    let mut changed = seal_request();
    changed.encapsulation_randomness[0] ^= 1;
    assert_ne!(
        proto_conformance::seal_base(&changed)?.encapsulated_key,
        actual.encapsulated_key
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn deterministic_sender_export_preserves_exporter_context_and_export_only_suite(
) -> Result<(), HpkeError> {
    for export_only in [false, true] {
        let mut request = export_request();
        let selected = if export_only {
            HpkeSuite::new(
                suite().kem,
                suite().kdf,
                crypto_hpke::HpkeAeadId::ExportOnly,
            )
        } else {
            suite()
        };
        request.suite = MessageField::some(HpkeSuiteIdentifier::try_from(selected)?);
        let native = HpkeDerandSenderExportRequest::try_from(&request)?;
        let expected = crypto_hpke::sender_export_derand(&native)?;
        let actual = proto_conformance::sender_export(&request)?;
        assert_eq!(actual.encapsulated_key, expected.encapsulated_key);
        assert_eq!(actual.exporter_secret, expected.exporter_secret());
        let mut changed = export_request();
        changed.suite = MessageField::some(HpkeSuiteIdentifier::try_from(selected)?);
        changed.exporter_context[0] ^= 1;
        assert_ne!(
            proto_conformance::sender_export(&changed)?.exporter_secret,
            actual.exporter_secret
        );
        let mut invalid = export_request();
        invalid.output_length = u32::MAX;
        let native = HpkeDerandSenderExportRequest::try_from(&invalid)?;
        let expected = crypto_hpke::sender_export_derand(&native).err().unwrap();
        assert!(matches!(proto_conformance::sender_export(&invalid),Err(e)if e==expected));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn deterministic_psk_setup_returns_live_native_context_with_public_descriptor(
) -> Result<(), HpkeError> {
    let request = psk_request();
    let native = HpkeDerandPskSenderSetupRequest::try_from(&request)?;
    let mut expected = crypto_hpke::setup_sender_psk_derand(&native)?;
    let (mut actual, public) = proto_conformance::setup_sender_psk(&request)?;
    assert_eq!(public.encapsulated_key, expected.encapsulated_key);
    let aad = [0, 255, 32, 0];
    let plaintext = [255, 0, 1];
    let first = actual.seal(&aad, &plaintext)?;
    assert_eq!(first, expected.context.seal(&aad, &plaintext)?);
    let second = actual.seal(&aad, &plaintext)?;
    assert_eq!(second, expected.context.seal(&aad, &plaintext)?);
    assert_ne!(first, second);
    let value = fixture();
    let private = hex_field(&value, "skRm");
    let mut receiver =
        crypto_hpke::setup_receiver_psk(&crypto_hpke::HpkePskReceiverSetupRequest {
            suite: suite(),
            encapsulated_key: &public.encapsulated_key,
            recipient_private_key: &private,
            info: &request.info,
            psk: HpkePskRef::new(&request.psk)?,
            psk_id: HpkePskIdRef::new(&request.psk_id)?,
        })?;
    assert_eq!(receiver.open(&aad, &first)?.plaintext.as_slice(), plaintext);
    assert_eq!(
        receiver.open(&aad, &second)?.plaintext.as_slice(),
        plaintext
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn explicit_randomness_psk_suite_and_unknown_modifier_errors_match_native() -> Result<(), HpkeError>
{
    for length in [0, 31, 33] {
        let mut seal = seal_request();
        seal.encapsulation_randomness = vec![0; length].into();
        let expected = crypto_hpke::seal_base_derand(&HpkeDerandSealRequest::try_from(&seal)?)
            .err()
            .unwrap();
        assert!(matches!(proto_conformance::seal_base(&seal),Err(e)if e==expected));
        let mut export = export_request();
        export.encapsulation_randomness = vec![0; length].into();
        let expected =
            crypto_hpke::sender_export_derand(&HpkeDerandSenderExportRequest::try_from(&export)?)
                .err()
                .unwrap();
        assert!(matches!(proto_conformance::sender_export(&export),Err(e)if e==expected));
        let mut setup = psk_request();
        setup.encapsulation_randomness = vec![0; length].into();
        let expected = crypto_hpke::setup_sender_psk_derand(
            &HpkeDerandPskSenderSetupRequest::try_from(&setup)?,
        )
        .err()
        .unwrap();
        assert!(matches!(proto_conformance::setup_sender_psk(&setup),Err(e)if e==expected));
    }
    let mut invalid = seal_request();
    invalid.recipient_public_key.clear();
    let expected = crypto_hpke::seal_base_derand(&HpkeDerandSealRequest::try_from(&invalid)?)
        .err()
        .unwrap();
    assert!(matches!(proto_conformance::seal_base(&invalid),Err(error)if error==expected));
    let mut invalid = export_request();
    invalid.recipient_public_key.clear();
    let expected =
        crypto_hpke::sender_export_derand(&HpkeDerandSenderExportRequest::try_from(&invalid)?)
            .err()
            .unwrap();
    assert!(matches!(proto_conformance::sender_export(&invalid),Err(error)if error==expected));
    let mut invalid = psk_request();
    invalid.recipient_public_key.clear();
    let expected =
        crypto_hpke::setup_sender_psk_derand(&HpkeDerandPskSenderSetupRequest::try_from(&invalid)?)
            .err()
            .unwrap();
    assert!(matches!(proto_conformance::setup_sender_psk(&invalid),Err(error)if error==expected));
    let unavailable = HpkeSuite::new(
        crypto_hpke::HpkeKemId::DhKemCp256HkdfSha256,
        suite().kdf,
        suite().aead,
    );
    let mut request = seal_request();
    request.suite = MessageField::some(HpkeSuiteIdentifier::try_from(unavailable)?);
    let expected = crypto_hpke::seal_base_derand(&HpkeDerandSealRequest::try_from(&request)?)
        .err()
        .unwrap();
    assert_eq!(expected, HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
    assert!(matches!(proto_conformance::seal_base(&request),Err(e)if e==expected));
    for field in [0, 1, 2] {
        for value in [0, -1, i32::MAX] {
            let mut request = seal_request();
            let mut identifier = HpkeSuiteIdentifier::try_from(suite())?;
            match field {
                0 => identifier.kem = value.into(),
                1 => identifier.kdf = value.into(),
                _ => identifier.aead = value.into(),
            };
            request.suite = MessageField::some(identifier);
            assert!(
                matches!(proto_conformance::seal_base(&request),Err(e)if e==HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM)
            );
        }
    }
    let mut bytes = seal_request().encode_to_vec();
    bytes.extend_from_slice(&[0xf8, 7, 1]);
    assert_eq!(
        decode_protobuf::<CryptoHpkeBaseSealConformanceRequest>(&bytes),
        Err(CryptoWireError::malformed_protobuf())
    );
    // Field 1 is the suite; its nested payload contains the same unknown tag.
    assert_eq!(
        decode_protobuf::<CryptoHpkeBaseSealConformanceRequest>(&[0x0a, 3, 0xf8, 7, 1]),
        Err(CryptoWireError::malformed_protobuf())
    );
    let mut setup = psk_request();
    setup.psk.clear();
    assert!(proto_conformance::setup_sender_psk(&setup).is_err());
    assert!(setup.psk.extend_from_slice(&[1; 32]).is_ok());
    setup.psk_id.clear();
    assert!(proto_conformance::setup_sender_psk(&setup).is_err());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn conformance_and_context_owners_clear_without_released_memory_reads() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoHpkeBaseSealConformanceRequest>();
    clearing::<CryptoHpkeSenderExportConformanceRequest>();
    clearing::<CryptoHpkePskSenderSetupConformanceRequest>();
    clearing::<crypto_hpke::HpkeSenderContext>();
    let mut request = psk_request();
    buffa::Message::clear(&mut request);
    assert!(request.psk.is_empty() || request.psk.iter().all(|b| *b == 0));
    assert!(
        request.encapsulation_randomness.is_empty()
            || request.encapsulation_randomness.iter().all(|b| *b == 0)
    );
}
