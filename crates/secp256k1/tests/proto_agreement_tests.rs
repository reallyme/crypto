// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(all(feature = "proto", any(feature = "native", feature = "wasm")))]

use buffa::Message;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoNativeAgreementResult, CryptoSecp256k1AgreementRequest,
};
use crypto_secp256k1::{
    derive_secp256k1_shared_secret, proto::derive_shared_secret, Secp256k1SharedSecret,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[path = "support/agreement_vectors.rs"]
mod vectors;

fn request(private: &[u8], public: &[u8]) -> CryptoSecp256k1AgreementRequest {
    CryptoSecp256k1AgreementRequest {
        private_key: private.to_vec().into(),
        peer_public_key_sec1: public.to_vec().into(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn published_scalar_multiplication_answers_bind_exact_raw_ecdh_bytes() -> Result<(), CryptoError> {
    let public = hex::decode(vectors::GENERATOR).unwrap();
    for (scalar, answer) in vectors::VECTORS {
        let private = Zeroizing::new(hex::decode(scalar).unwrap());
        let expected = Zeroizing::new(hex::decode(answer).unwrap());
        let request = request(&private, &public);
        let native = derive_secp256k1_shared_secret(&private, &public)?;
        assert_eq!(native.as_bytes().as_slice(), expected.as_slice());
        let output = derive_shared_secret(&request)?;
        assert_eq!(output.shared_secret, expected.as_slice());
        assert_eq!(output.shared_secret.len(), 32);
        assert_eq!(request.private_key, private.as_slice());
        assert_eq!(request.peer_public_key_sec1, public);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn scalar_and_point_errors_preserve_native_encoding_and_range_policy() {
    let public = hex::decode(vectors::GENERATOR).unwrap();
    for private in [
        vec![],
        vec![1; 31],
        vec![1; 33],
        vec![0; 32],
        vec![255; 32],
        hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap(),
    ] {
        assert_eq!(
            derive_shared_secret(&request(&private, &public)).err(),
            Some(CryptoError::PRIMITIVE_INVALID_KEY)
        );
    }
    let mut private = Zeroizing::new([0; 32]);
    private[31] = 1;
    let mut compressed = vec![2];
    compressed.extend_from_slice(&public[1..33]);
    let mut hybrid = public.clone();
    hybrid[0] = 6;
    let mut off_curve = vec![0; 65];
    off_curve[0] = 4;
    let mut too_long = public.clone();
    too_long.push(0);
    for invalid in [
        vec![],
        vec![0],
        compressed,
        hybrid,
        off_curve,
        public[..64].to_vec(),
        too_long,
    ] {
        assert_eq!(
            derive_shared_secret(&request(private.as_slice(), &invalid)).err(),
            Some(CryptoError::PRIMITIVE_INVALID_KEY)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unknown_modifiers_and_wire_bytes_are_explicit() {
    assert_eq!(
        crypto_proto::wire::decode_protobuf::<CryptoSecp256k1AgreementRequest>(&[
            0xa2, 6, 4, 0, 255, 1, 0
        ]),
        Err(crypto_proto::wire::CryptoWireError::malformed_protobuf())
    );
    let request = request(&[0, 255, 32, 0], &[4, 1, 0]);
    assert_eq!(
        request.encode_to_vec(),
        [10, 4, 0, 255, 32, 0, 18, 3, 4, 1, 0]
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_secret_and_transport_result_keep_independent_clearing_storage() -> Result<(), CryptoError>
{
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<Secp256k1SharedSecret>();
    clearing::<CryptoSecp256k1AgreementRequest>();
    clearing::<CryptoNativeAgreementResult>();
    let public = hex::decode(vectors::GENERATOR).unwrap();
    let private = Zeroizing::new(hex::decode(vectors::VECTORS[0].0).unwrap());
    let request = request(&private, &public);
    let mut native = derive_secp256k1_shared_secret(&private, &public)?;
    let mut result = derive_shared_secret(&request)?;
    let expected = Zeroizing::new(result.shared_secret.clone());
    native.zeroize();
    assert!(native.as_bytes().iter().all(|byte| *byte == 0));
    assert_eq!(result.shared_secret, expected.as_slice());
    Message::clear(&mut result);
    assert!(result.shared_secret.is_empty());
    assert_eq!(request.private_key, private.as_slice());
    Ok(())
}
