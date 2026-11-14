// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Populate clearing generated owners.
#![cfg(all(feature = "proto", feature = "native"))]

use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeAgreementResult, CryptoNativeKeyGenerateRequest, CryptoNativePublicKeyRequest,
    CryptoX448AgreementRequest, CryptoX448KeyDescriptor, CryptoX448PrivateKeyInput,
    CryptoX448PublicKey,
};
use crypto_x448::{contract, X448PrivateKey, X448PublicKey};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn imports_and_agreement_preserve_native_bytes_and_owners() -> Result<(), CryptoError> {
    let mut source = CryptoX448PrivateKeyInput::default();
    assert!(source.scalar.extend_from_slice(&[7; 56]).is_ok());
    let key = X448PrivateKey::try_from(&source)?;
    let (derived, public) = contract::generate_from_seed(&source)?;
    assert_eq!(public, X448PublicKey::from(&key));
    let descriptor = contract::describe(&derived)?;
    assert_eq!(
        descriptor
            .public_key
            .as_option()
            .unwrap()
            .u_coordinate
            .as_slice(),
        public.as_bytes().as_slice()
    );
    let caps = descriptor.capabilities.as_option().unwrap();
    assert!(
        caps.supports_agreement
            && caps.exposes_private_bytes
            && caps.zeroizes_private_storage_on_drop
    );
    assert!(!caps.supports_signing && !caps.provider_managed_cleanup);
    let peer = X448PrivateKey::from_array([13; 56]);
    let mut request = CryptoX448AgreementRequest::default();
    request.peer_public_key =
        MessageField::some(CryptoX448PublicKey::try_from(&X448PublicKey::from(&peer))?);
    let actual = contract::agree(&key, &request)?;
    let expected = crypto_x448::derive_x448_shared_secret(&key, X448PublicKey::from(&peer))?;
    assert_eq!(actual.as_bytes(), expected.as_bytes().as_slice());
    assert_eq!(
        contract::agreement_result(&actual)?
            .shared_secret
            .as_slice(),
        expected.as_bytes().as_slice()
    );
    assert_eq!(source.scalar, [7; 56]);
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn absent_unknown_and_invalid_peer_inputs_fail_closed() {
    let key = X448PrivateKey::from_array([7; 56]);
    assert!(
        matches!(contract::agree(&key,&CryptoX448AgreementRequest::default()),Err(error) if error==CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut source = CryptoX448PrivateKeyInput::default();
    assert!(source.scalar.extend_from_slice(&[7; 56]).is_ok());
    assert_unknown_wire(&source, &[0xa0, 0x06, 1]);
    for length in [0, 55, 57] {
        let mut source = CryptoX448PrivateKeyInput::default();
        assert!(source.scalar.resize(length, 7).is_ok());
        assert!(
            matches!(X448PrivateKey::try_from(&source),Err(error) if error==CryptoError::PRIMITIVE_INVALID_KEY)
        );
    }
    let mut public = CryptoX448PublicKey::default();
    assert!(public.u_coordinate.resize(56, 0).is_ok());
    assert!(
        matches!(X448PublicKey::try_from(&public),Err(error) if error==CryptoError::PRIMITIVE_INVALID_KEY)
    );
    let generate = CryptoNativeKeyGenerateRequest::default();
    assert_unknown_wire(&generate, &[0xa0, 0x06, 1]);
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn transport_owners_and_nested_unknown_storage_keep_drop_cleanup() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoX448PrivateKeyInput>();
    require_cleanup::<CryptoX448PublicKey>();
    require_cleanup::<CryptoX448AgreementRequest>();
    require_cleanup::<CryptoX448KeyDescriptor>();
    require_cleanup::<CryptoNativeAgreementResult>();
    require_cleanup::<CryptoNativeKeyGenerateRequest>();
    require_cleanup::<CryptoNativePublicKeyRequest>();
}

fn assert_unknown_wire<M: buffa::Message>(message: &M, modifier: &[u8]) {
    let mut wire = message.encode_to_vec();
    wire.extend_from_slice(modifier);
    assert!(matches!(crypto_proto::wire::decode_protobuf::<M>(&wire),
        Err(error) if error == crypto_proto::wire::CryptoWireError::malformed_protobuf()));
}
