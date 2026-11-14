// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed Base injected entropy preserves bytes and existing provider failures.

#![cfg(all(feature = "proto", feature = "base-p256-aes128gcm"))]
#![allow(missing_docs, clippy::expect_used)]

use crypto_hpke::base_p256::{
    self, P256BaseRandomError, P256BaseRng, P256RecipientKey, PRIVATE_KEY_LEN,
};
use crypto_hpke::proto_protocol::P256BaseSealInputs;
use crypto_hpke::HpkeError;
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoHpkeP256BaseSealRequest;
use zeroize::Zeroizing;

struct Fixed(Zeroizing<Vec<u8>>);
impl P256BaseRng for Fixed {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError> {
        assert_eq!(output.len(), PRIVATE_KEY_LEN);
        assert_eq!(output.len(), self.0.len());
        output.copy_from_slice(&self.0);
        Ok(())
    }
}
struct Fails;
impl P256BaseRng for Fails {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError> {
        output.fill(0xa5);
        Err(P256BaseRandomError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("data/base_p256.json")).expect("published RFC fixture")
}
fn bytes(value: &serde_json::Value) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(hex::decode(value.as_str().expect("fixed hex")).expect("public fixture"))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn injected_seal_matches_native_enc_and_ciphertext_for_exact_binary_context(
) -> Result<(), HpkeError> {
    let vector = fixture();
    let recipient = P256RecipientKey::import(&bytes(&vector["skRm"]))?;
    let mut request = CryptoHpkeP256BaseSealRequest::default();
    assert!(request
        .recipient_public_key
        .extend_from_slice(recipient.public_key())
        .is_ok());
    assert!(request
        .info
        .extend_from_slice(&[0, 0xff, 0xc3, 0xa9, 0x00, 0x80])
        .is_ok());
    assert!(request
        .plaintext
        .extend_from_slice(&[0xff, 0, 1, 0x80, 0])
        .is_ok());
    let native = base_p256::seal_with_rng(
        &request.recipient_public_key,
        &request.info,
        &request.plaintext,
        &mut Fixed(bytes(&vector["ikmE"])),
    )?;
    let sealed = P256BaseSealInputs::try_from(&request)?
        .seal_with_rng(&mut Fixed(bytes(&vector["ikmE"])))?;
    assert_eq!(sealed.enc, native.enc);
    assert_eq!(sealed.ciphertext, native.ciphertext);
    assert_eq!(
        base_p256::open(&recipient, &sealed.enc, &request.info, &sealed.ciphertext)?.as_slice(),
        request.plaintext.as_slice(),
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn injected_seal_propagates_the_native_entropy_failure() -> Result<(), HpkeError> {
    let vector = fixture();
    let mut request = CryptoHpkeP256BaseSealRequest::default();
    assert!(request
        .recipient_public_key
        .extend_from_slice(&bytes(&vector["pkRm"]))
        .is_ok());
    assert!(request.info.extend_from_slice(&[0, 0xff]).is_ok());
    assert!(request.plaintext.extend_from_slice(&[0xa5, 0]).is_ok());
    let inputs = P256BaseSealInputs::try_from(&request)?;
    assert_eq!(
        inputs.seal_with_rng(&mut Fails).err(),
        Some(HpkeError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    );
    assert_eq!(
        base_p256::seal_with_rng(
            &request.recipient_public_key,
            &request.info,
            &request.plaintext,
            &mut Fails
        )
        .err(),
        Some(HpkeError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    );
    Ok(())
}
