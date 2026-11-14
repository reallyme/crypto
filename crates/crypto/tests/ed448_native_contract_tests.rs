// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Populate clearing generated owners.
#![cfg(all(feature = "operation-response", feature = "ed448"))]

use buffa::{EnumValue, Enumeration};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoEd448KeyImportRequest, CryptoEd448OrdinarySignRequest, CryptoEd448OrdinaryVerifyRequest,
    CryptoNativeKeyGenerateRequest, Ed448Operation as ProtoOperation,
};
use reallyme_crypto::ed448::{contract, Ed448Key, Ed448Operation, OpaqueEd448Signer};
use reallyme_crypto::key_random::KeyRng;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_generated_operation_has_exact_native_parity() {
    for value in ProtoOperation::values() {
        match Ed448Operation::try_from(EnumValue::from(*value)) {
            Ok(native) => assert_eq!(ProtoOperation::from(native), *value),
            Err(error) => {
                assert_eq!(value.to_i32(), 0);
                assert_eq!(error, CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
            }
        }
    }
    for number in [i32::MIN, -1, 1, 99, 999, i32::MAX] {
        assert_eq!(
            Ed448Operation::try_from(EnumValue::<ProtoOperation>::from(number)),
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_ordinary_rfc8032_cases_pass_through_protected_adapters() -> Result<(), CryptoError> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("data/ed448_rfc8032.json")).unwrap();
    let mut executed = 0;
    for value in fixture["vectors"].as_array().unwrap() {
        if value["prehash"] != "false" || value["context"] != "" {
            continue;
        }
        let mut source = CryptoEd448KeyImportRequest::default();
        source.seed = hex::decode(value["seed"].as_str().unwrap()).unwrap().into();
        let key = Ed448Key::try_from(&source)?;
        let mut sign = CryptoEd448OrdinarySignRequest::default();
        sign.message = hex::decode(value["message"].as_str().unwrap())
            .unwrap()
            .into();
        let result = contract::sign(&key, &sign)?;
        assert_eq!(
            result.signature,
            hex::decode(value["signature"].as_str().unwrap()).unwrap()
        );
        let mut verify = CryptoEd448OrdinaryVerifyRequest::default();
        assert!(verify
            .public_key
            .extend_from_slice(key.public_key())
            .is_ok());
        assert!(verify.message.extend_from_slice(&sign.message).is_ok());
        assert!(verify
            .signature
            .extend_from_slice(&result.signature)
            .is_ok());
        contract::verify(&verify)?;
        assert!(verify.message.push(0).is_ok());
        assert!(matches!(contract::verify(&verify),
            Err(error) if error == CryptoError::PRIMITIVE_INVALID_SIGNATURE));
        executed += 1;
    }
    assert_eq!(executed, 8);
    Ok(())
}

struct FailingRng;
impl KeyRng for FailingRng {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        destination.fill(9);
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}
struct Provider(Ed448Key);
impl OpaqueEd448Signer for Provider {
    fn public_key(&self) -> &[u8; 57] {
        self.0.public_key()
    }
    fn sign_message(&self, message: &[u8]) -> Result<[u8; 114], CryptoError> {
        self.0.sign(message)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn empty_message_opaque_signing_unknown_context_and_entropy_failure_are_explicit(
) -> Result<(), CryptoError> {
    let mut source = CryptoEd448KeyImportRequest::default();
    assert!(source.seed.resize(57, 0).is_ok());
    let key = Ed448Key::try_from(&source)?;
    let provider = Provider(Ed448Key::try_from(&source)?);
    let empty = CryptoEd448OrdinarySignRequest::default();
    assert_eq!(
        contract::sign(&key, &empty)?.signature,
        contract::sign_opaque(&provider, &empty)?.signature
    );
    let context = CryptoEd448OrdinarySignRequest::default();
    assert_unknown_wire(&context, &[0xa2, 0x06, 1, 1]);
    assert!(
        matches!(contract::generate_with_rng(&CryptoNativeKeyGenerateRequest::default(), &mut FailingRng),
        Err(error) if error == CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    );
    for length in [0, 56, 58] {
        let mut source = CryptoEd448KeyImportRequest::default();
        assert!(source.seed.resize(length, 1).is_ok());
        assert!(matches!(Ed448Key::try_from(&source),
            Err(error) if error == CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_and_nested_transport_owners_keep_drop_cleanup() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<Ed448Key>();
    require_cleanup::<CryptoEd448KeyImportRequest>();
    require_cleanup::<CryptoEd448OrdinarySignRequest>();
    require_cleanup::<CryptoEd448OrdinaryVerifyRequest>();
    require_cleanup::<CryptoNativeKeyGenerateRequest>();
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
