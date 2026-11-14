// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Construct clearing owners before populating bytes.
#![cfg(all(feature = "operation-response", feature = "ecdsa-explicit"))]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_ecdsa_input::Input, CryptoEcdsaAgreementRequest,
    CryptoEcdsaCurveIdentifier, CryptoEcdsaInput, CryptoEcdsaKeyImportRequest,
    CryptoEcdsaMessageInput, CryptoEcdsaPrehashInput, CryptoEcdsaSignOptions,
    CryptoEcdsaSignRequest, CryptoEcdsaVerifyRequest, CryptoNativePublicKeyRequest,
    EcdsaCurve as ProtoCurve, EcdsaEncoding as ProtoEncoding, HashAlgorithm,
};
use reallyme_crypto::ecdsa_explicit::{
    contract, EcdsaCurve, EcdsaEncoding, EcdsaHash, EcdsaInput, EcdsaKey, OpaqueEcdsaSigner,
};

fn message(bytes: &[u8]) -> CryptoEcdsaInput {
    let mut body = CryptoEcdsaMessageInput::default();
    body.hash = HashAlgorithm::HASH_ALGORITHM_SHA2_256.into();
    assert!(body.message.extend_from_slice(bytes).is_ok());
    let mut output = CryptoEcdsaInput::default();
    output.input = Some(Input::Message(Box::new(body)));
    output
}
fn options() -> CryptoEcdsaSignOptions {
    let mut output = CryptoEcdsaSignOptions::default();
    output.encoding = ProtoEncoding::ECDSA_ENCODING_FIXED_WIDTH.into();
    output
}
fn request(bytes: &[u8]) -> CryptoEcdsaSignRequest {
    let mut output = CryptoEcdsaSignRequest::default();
    output.input = MessageField::some(message(bytes));
    output.options = MessageField::some(options());
    output
}
fn import() -> CryptoEcdsaKeyImportRequest {
    let mut curve = CryptoEcdsaCurveIdentifier::default();
    curve.curve = ProtoCurve::ECDSA_CURVE_NIST_P256.into();
    let mut output = CryptoEcdsaKeyImportRequest::default();
    output.curve = MessageField::some(curve);
    assert!(output.scalar.resize(32, 0).is_ok());
    output.scalar[31] = 1;
    output
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn encoding_and_hash_bridges_cover_every_generated_value() {
    for value in ProtoEncoding::values() {
        match EcdsaEncoding::try_from(EnumValue::from(*value)) {
            Ok(native) => assert_eq!(ProtoEncoding::from(native), *value),
            Err(error) => {
                assert_eq!(value.to_i32(), 0);
                assert_eq!(error, CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
            }
        }
    }
    for value in HashAlgorithm::values() {
        let native = EcdsaHash::try_from(EnumValue::from(*value));
        if matches!(
            value,
            HashAlgorithm::HASH_ALGORITHM_SHA2_256
                | HashAlgorithm::HASH_ALGORITHM_SHA2_384
                | HashAlgorithm::HASH_ALGORITHM_SHA2_512
        ) {
            assert_eq!(HashAlgorithm::from(native.unwrap()), *value);
        } else {
            assert_eq!(native, Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM));
        }
    }
    for unknown in [i32::MIN, -1, 1, 99, 999, i32::MAX] {
        assert_eq!(
            EcdsaEncoding::try_from(EnumValue::<ProtoEncoding>::from(unknown)),
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn input_presence_exact_borrow_and_wire_known_answers() -> Result<(), CryptoError> {
    let input = message(&[0, 255, 32, 0]);
    let EcdsaInput::Message { hash, bytes } = EcdsaInput::try_from(&input)? else {
        return Err(CryptoError::BACKEND_INTERNAL);
    };
    assert_eq!(hash, EcdsaHash::Sha256);
    assert_eq!(bytes, &[0, 255, 32, 0]);
    let Some(Input::Message(source)) = input.input.as_ref() else {
        return Err(CryptoError::BACKEND_INTERNAL);
    };
    assert_eq!(bytes.as_ptr(), source.message.as_ptr());
    assert!(matches!(EcdsaInput::try_from(&CryptoEcdsaInput::default()),
        Err(error) if error == CryptoError::PRIMITIVE_INVALID_PARAMETER));
    let empty = message(&[]);
    assert!(matches!(
        EcdsaInput::try_from(&empty),
        Ok(EcdsaInput::Message { bytes: [], .. })
    ));
    assert_eq!(empty.encode_to_vec(), [0x0a, 2, 8, 0x64]);
    assert_eq!(
        message(b"abc").encode_to_vec(),
        [0x0a, 7, 8, 0x64, 0x12, 3, 0x61, 0x62, 0x63]
    );
    let decoded = CryptoEcdsaInput::decode_from_slice(&empty.encode_to_vec()).unwrap();
    assert!(matches!(
        EcdsaInput::try_from(&decoded),
        Ok(EcdsaInput::Message { bytes: [], .. })
    ));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn invalid_prehash_unknown_modifiers_and_absent_options_fail_closed() {
    for (hash, width) in [
        (HashAlgorithm::HASH_ALGORITHM_SHA2_256, 32),
        (HashAlgorithm::HASH_ALGORITHM_SHA2_384, 48),
        (HashAlgorithm::HASH_ALGORITHM_SHA2_512, 64),
    ] {
        for length in [0, width - 1, width + 1] {
            let mut body = CryptoEcdsaPrehashInput::default();
            body.hash = hash.into();
            assert!(body.digest.resize(length, 7).is_ok());
            let mut input = CryptoEcdsaInput::default();
            input.input = Some(Input::Prehash(Box::new(body)));
            assert!(matches!(EcdsaInput::try_from(&input),
                Err(error) if error == CryptoError::PRIMITIVE_INVALID_LENGTH));
        }
    }
    let mut input = message(b"exact");
    assert_unknown_wire(&input, &[0xa0, 0x06, 1]);
    let mut body = CryptoEcdsaMessageInput::default();
    body.hash = HashAlgorithm::HASH_ALGORITHM_SHA2_256.into();
    let mut modified_child = body.encode_to_vec();
    modified_child.extend_from_slice(&[0xa0, 0x06, 1]);
    input.input = Some(Input::Message(Box::new(body)));
    let mut modified = input.encode_to_vec();
    // The duplicate child retains protobuf merge semantics but the unknown
    // modifier must fail admission before any operation uses the message.
    buffa::encoding::encode_varint((1u64 << 3) | 2, &mut modified);
    buffa::encoding::encode_varint(
        u64::try_from(modified_child.len()).unwrap_or(u64::MAX),
        &mut modified,
    );
    modified.extend_from_slice(&modified_child);
    assert!(crypto_proto::wire::decode_protobuf::<CryptoEcdsaInput>(&modified).is_err());
    let key = EcdsaKey::try_from(&import()).unwrap();
    assert!(
        matches!(contract::sign(&key, &CryptoEcdsaSignRequest::default()),
        Err(error) if error == CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn message_and_prehash_signing_preserve_native_results() -> Result<(), CryptoError> {
    let source = import();
    let key = EcdsaKey::try_from(&source)?;
    let request = request(b"exact TBS bytes\0");
    let signature = contract::sign(&key, &request)?;
    let digest = reallyme_crypto::sha2::digest(b"exact TBS bytes\0");
    let mut body = CryptoEcdsaPrehashInput::default();
    body.hash = HashAlgorithm::HASH_ALGORITHM_SHA2_256.into();
    assert!(body.digest.extend_from_slice(digest.as_bytes()).is_ok());
    let mut input = CryptoEcdsaInput::default();
    input.input = Some(Input::Prehash(Box::new(body)));
    let mut prehash = CryptoEcdsaSignRequest::default();
    prehash.input = MessageField::some(input);
    prehash.options = MessageField::some(options());
    assert_eq!(
        contract::sign(&key, &prehash)?.signature,
        signature.signature
    );
    let mut verify = CryptoEcdsaVerifyRequest::default();
    verify.public_key = MessageField::some(contract::public_key(
        &key,
        &CryptoNativePublicKeyRequest::default(),
    )?);
    verify.input = MessageField::some(message(b"exact TBS bytes\0"));
    verify.options = MessageField::some(options());
    assert!(verify
        .signature
        .extend_from_slice(&signature.signature)
        .is_ok());
    contract::verify(&verify)?;
    verify.input = MessageField::some(message(b"changed TBS bytes\0"));
    assert!(
        matches!(contract::verify(&verify), Err(error) if error == CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    );
    let descriptor = contract::describe_software(&key)?;
    let capabilities = descriptor.capabilities.as_option().unwrap();
    assert!(
        capabilities.supports_signing
            && capabilities.supports_agreement
            && capabilities.zeroizes_private_storage_on_drop
    );
    assert!(!capabilities.exposes_private_bytes);
    assert_eq!(source.scalar[31], 1);
    Ok(())
}

struct Provider {
    key: EcdsaKey,
    denied: bool,
}
impl OpaqueEcdsaSigner for Provider {
    fn curve(&self) -> EcdsaCurve {
        self.key.curve()
    }
    fn public_key(&self) -> &[u8] {
        self.key.public_key()
    }
    fn sign_prehash(
        &self,
        hash: EcdsaHash,
        digest: &[u8],
        encoding: EcdsaEncoding,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.denied {
            return Err(CryptoError::PROVIDER_ACCESS_DENIED);
        }
        self.key.sign(
            EcdsaInput::Prehash {
                hash,
                bytes: digest,
            },
            encoding,
        )
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn opaque_provider_keeps_typed_failure_and_nonexporting_capabilities() -> Result<(), CryptoError> {
    let mut provider = Provider {
        key: EcdsaKey::try_from(&import())?,
        denied: false,
    };
    let request = request(b"exact\0provider bytes");
    assert_eq!(
        contract::sign_opaque(&provider, &request)?.signature,
        contract::sign(&provider.key, &request)?.signature
    );
    let descriptor = contract::describe_opaque(&provider)?;
    let capabilities = descriptor.capabilities.as_option().unwrap();
    assert!(capabilities.supports_signing && capabilities.provider_managed_cleanup);
    assert!(
        !capabilities.supports_agreement
            && !capabilities.exposes_private_bytes
            && !capabilities.zeroizes_private_storage_on_drop
    );
    provider.denied = true;
    assert!(matches!(contract::sign_opaque(&provider, &request),
        Err(error) if error == CryptoError::PROVIDER_ACCESS_DENIED));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_and_transport_owners_have_drop_cleanup() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<EcdsaKey>();
    require_cleanup::<CryptoEcdsaInput>();
    require_cleanup::<CryptoEcdsaMessageInput>();
    require_cleanup::<CryptoEcdsaPrehashInput>();
    require_cleanup::<CryptoEcdsaKeyImportRequest>();
    require_cleanup::<CryptoEcdsaSignRequest>();
    require_cleanup::<CryptoEcdsaVerifyRequest>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn agreement_adapter_preserves_native_clearing_result_and_key_errors() -> Result<(), CryptoError> {
    let key = EcdsaKey::try_from(&import())?;
    let mut request = CryptoEcdsaAgreementRequest::default();
    assert!(request
        .peer_sec1
        .extend_from_slice(key.public_key())
        .is_ok());
    let native = key.agree(key.public_key())?;
    let adapted = contract::agree(&key, &request)?;
    assert_eq!(
        contract::agreement_result(&adapted)?.shared_secret,
        contract::agreement_result(&native)?.shared_secret
    );
    request.peer_sec1.resize(1, 0)?;
    assert!(
        matches!(contract::agree(&key, &request), Err(error) if error == CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY)
    );
    Ok(())
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
