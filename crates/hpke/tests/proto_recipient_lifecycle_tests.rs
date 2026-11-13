// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed Base recipient import/generation retain exact native ownership.

#![cfg(all(feature = "proto", feature = "base-p256-aes128gcm"))]
#![allow(missing_docs, clippy::expect_used)]

use buffa::Message;
use crypto_hpke::base_p256::{
    open, seal_with_rng, P256BaseRandomError, P256BaseRng, P256RecipientKey, PRIVATE_KEY_LEN,
};
use crypto_hpke::proto_protocol::{P256BaseRecipientGenerateInputs, P256BaseRecipientImportInputs};
use crypto_hpke::HpkeError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHpkeP256BasePublicKey, CryptoHpkeP256BaseRecipientGenerateRequest,
    CryptoHpkeP256BaseRecipientImportRequest,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("data/base_p256.json")).expect("published RFC fixture")
}

fn bytes(value: &serde_json::Value) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(hex::decode(value.as_str().expect("fixed hex field")).expect("fixed fixture"))
}

struct Fixed {
    bytes: Zeroizing<Vec<u8>>,
    calls: usize,
}
impl P256BaseRng for Fixed {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError> {
        assert_eq!(output.len(), PRIVATE_KEY_LEN);
        assert_eq!(output.len(), self.bytes.len());
        self.calls = self.calls.checked_add(1).expect("bounded fixture counter");
        output.copy_from_slice(&self.bytes);
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

fn import_request(private: &[u8]) -> CryptoHpkeP256BaseRecipientImportRequest {
    let mut output = CryptoHpkeP256BaseRecipientImportRequest::default();
    output.private_key.extend_from_slice(private);
    output
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn imported_recipient_and_public_descriptor_match_the_existing_rfc_owner() -> Result<(), HpkeError>
{
    let vector = fixture();
    let request = import_request(&bytes(&vector["skRm"]));
    let native = P256RecipientKey::import(&request.private_key)?;
    let mut input = P256BaseRecipientImportInputs::try_from(&request)?;
    let (recipient, descriptor) = input.import()?;
    assert_eq!(recipient.public_key(), native.public_key());
    assert_eq!(descriptor.public_key, recipient.public_key().as_slice());
    assert_eq!(descriptor.public_key, bytes(&vector["pkRm"]).as_slice());
    input.zeroize();
    assert_eq!(
        input.import().err(),
        Some(HpkeError::PRIMITIVE_INVALID_PRIVATE_KEY)
    );
    assert!(!request.private_key.is_empty());
    assert!(!descriptor.public_key.is_empty());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn explicit_rng_generation_matches_rfc_derivation_without_private_export() -> Result<(), HpkeError>
{
    let vector = fixture();
    let request = CryptoHpkeP256BaseRecipientGenerateRequest::default();
    let inputs = P256BaseRecipientGenerateInputs::try_from(&request)?;
    let mut rng = Fixed {
        bytes: bytes(&vector["ikmR"]),
        calls: 0,
    };
    let (recipient, descriptor) = inputs.generate_with_rng(&mut rng)?;
    assert_eq!(rng.calls, 1);
    assert_eq!(descriptor.public_key, bytes(&vector["pkRm"]).as_slice());
    assert_eq!(descriptor.public_key, recipient.public_key().as_slice());
    let sealed = seal_with_rng(
        &descriptor.public_key,
        &bytes(&vector["info"]),
        &bytes(&vector["encryption"]["pt"]),
        &mut Fixed {
            bytes: bytes(&vector["ikmE"]),
            calls: 0,
        },
    )?;
    let plaintext = open(
        &recipient,
        &sealed.enc,
        &bytes(&vector["info"]),
        &sealed.ciphertext,
    )?;
    assert_eq!(
        plaintext.as_slice(),
        bytes(&vector["encryption"]["pt"]).as_slice()
    );
    assert_eq!(
        inputs.generate_with_rng(&mut Fails).err(),
        Some(HpkeError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn operating_system_generation_returns_the_fixed_native_owner_and_public_descriptor(
) -> Result<(), HpkeError> {
    let inputs = P256BaseRecipientGenerateInputs::try_from(
        &CryptoHpkeP256BaseRecipientGenerateRequest::default(),
    )?;
    let (recipient, descriptor) = inputs.generate()?;
    assert_eq!(descriptor.public_key, recipient.public_key().as_slice());
    assert_eq!(
        descriptor.public_key.len(),
        crypto_hpke::base_p256::PUBLIC_KEY_LEN
    );
    assert_eq!(descriptor.public_key.first(), Some(&0x04));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn import_preserves_exact_width_and_native_scalar_range_errors() {
    for length in [
        0,
        1,
        PRIVATE_KEY_LEN.checked_sub(1).expect("fixed width"),
        PRIVATE_KEY_LEN.checked_add(1).expect("fixed width"),
    ] {
        let request = import_request(&vec![1; length]);
        assert_eq!(
            P256BaseRecipientImportInputs::try_from(&request).err(),
            Some(HpkeError::PRIMITIVE_INVALID_PRIVATE_KEY)
        );
    }
    for private in [[0; PRIVATE_KEY_LEN], [0xff; PRIVATE_KEY_LEN]] {
        let request = import_request(&private);
        assert_eq!(
            P256BaseRecipientImportInputs::try_from(&request)
                .expect("exact width")
                .import()
                .err(),
            Some(HpkeError::PRIMITIVE_INVALID_PRIVATE_KEY)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn lifecycle_requests_reject_unknown_modifiers_and_keep_clearing_owners(
) -> Result<(), buffa::DecodeError> {
    fn requires_owner<T: ZeroizeOnDrop>() {}
    requires_owner::<P256RecipientKey>();
    requires_owner::<CryptoHpkeP256BasePublicKey>();
    requires_owner::<CryptoHpkeP256BaseRecipientImportRequest>();
    requires_owner::<CryptoHpkeP256BaseRecipientGenerateRequest>();
    requires_owner::<P256BaseRecipientImportInputs>();
    let mut request = CryptoHpkeP256BaseRecipientGenerateRequest::default();
    request.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        P256BaseRecipientGenerateInputs::try_from(&request).err(),
        Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    let vector = fixture();
    let mut request = import_request(&bytes(&vector["skRm"]));
    request.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        P256BaseRecipientImportInputs::try_from(&request).err(),
        Some(HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}
