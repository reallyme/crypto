// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(feature = "operation-response")]

use buffa::Message;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoP256SecureEnclaveHandleDecodeRequest, CryptoP256SecureEnclaveHandleDecodeResult,
    CryptoP256SecureEnclaveHandleEncodeRequest, CryptoP256SecureEnclaveHandleEncodeResult,
};
use reallyme_crypto::format_contract::{decode_p256_handle, encode_p256_handle};
use zeroize::ZeroizeOnDrop;

#[cfg(any(feature = "p256", feature = "ecdsa-explicit"))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn exact_binary_and_empty_handle_tags_match_existing_prefix_helpers() -> Result<(), CryptoError> {
    for tag in [
        &[][..],
        b"tag".as_slice(),
        &[0, 255, 32, 0][..],
        b"SE:tag".as_slice(),
    ] {
        let mut request = CryptoP256SecureEnclaveHandleEncodeRequest::default();
        assert!(request.tag.extend_from_slice(tag).is_ok());
        let output = encode_p256_handle(&request)?;
        assert_eq!(output.handle, crypto_p256::encode_se_handle(tag)?);
        let mut request = CryptoP256SecureEnclaveHandleDecodeRequest::default();
        assert!(request.handle.extend_from_slice(&output.handle).is_ok());
        let decoded = decode_p256_handle(&request)?;
        assert_eq!(decoded.tag.as_deref(), Some(tag));
        assert_eq!(
            decoded.tag.as_deref(),
            crypto_p256::decode_se_handle(&request.handle)
        );
    }
    let mut request = CryptoP256SecureEnclaveHandleDecodeRequest::default();
    assert!(request
        .handle
        .extend_from_slice(crypto_p256::SE_HANDLE_PREFIX)
        .is_ok());
    let empty = decode_p256_handle(&request)?;
    assert_eq!(empty.encode_to_vec(), [10, 0]);
    for non_handle in [
        &[][..],
        b"se:tag".as_slice(),
        b"SE".as_slice(),
        b" SE:tag".as_slice(),
    ] {
        let mut request = CryptoP256SecureEnclaveHandleDecodeRequest::default();
        assert!(request.handle.extend_from_slice(non_handle).is_ok());
        let decoded = decode_p256_handle(&request)?;
        assert!(decoded.tag.is_none());
        assert!(decoded.encode_to_vec().is_empty());
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unknown_handle_modifiers_and_clearing_storage_are_explicit() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoP256SecureEnclaveHandleEncodeRequest>();
    clearing::<CryptoP256SecureEnclaveHandleEncodeResult>();
    clearing::<CryptoP256SecureEnclaveHandleDecodeRequest>();
    clearing::<CryptoP256SecureEnclaveHandleDecodeResult>();
    use crypto_proto::wire::{decode_protobuf, CryptoWireError};
    assert_eq!(
        decode_protobuf::<CryptoP256SecureEnclaveHandleEncodeRequest>(&[10, 1, 255, 0xf8, 7, 1]),
        Err(CryptoWireError::malformed_protobuf())
    );
    assert_eq!(
        decode_protobuf::<CryptoP256SecureEnclaveHandleDecodeRequest>(&[
            10, 3, b'S', b'E', b':', 0xf8, 7, 1
        ]),
        Err(CryptoWireError::malformed_protobuf())
    );
    let mut decoded =
        CryptoP256SecureEnclaveHandleDecodeResult::decode_from_slice(&[10, 4, 0, 255, 32, 0])
            .unwrap();
    assert_eq!(decoded.tag.as_deref(), Some(&[0, 255, 32, 0][..]));
    buffa::Message::clear(&mut decoded);
    assert!(decoded
        .tag
        .as_ref()
        .is_none_or(|bytes| bytes.iter().all(|byte| *byte == 0)));
}

#[cfg(not(any(feature = "p256", feature = "ecdsa-explicit")))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn handle_metadata_does_not_enable_p256() {
    assert!(
        matches!(encode_p256_handle(&CryptoP256SecureEnclaveHandleEncodeRequest::default()),Err(e)if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    assert!(
        matches!(decode_p256_handle(&CryptoP256SecureEnclaveHandleDecodeRequest::default()),Err(e)if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}
