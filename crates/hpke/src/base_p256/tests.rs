// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hpke::{Deserializable, Kem as KemTrait, OpModeR, Serializable};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    open, seal_with_rng, Aead, Kdf, Kem, P256BaseError, P256BaseRandomError, P256BaseRng,
    P256RecipientKey, INFO_MAX_LEN, PLAINTEXT_MAX_LEN, PRIVATE_KEY_LEN,
};

fn vector() -> Value {
    serde_json::from_str(include_str!("../../tests/data/base_p256.json"))
        .expect("valid public fixture")
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex fixture field")).expect("hex fixture")
}

struct Fixed(Vec<u8>);

impl P256BaseRng for Fixed {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError> {
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rfc9180_a3_1_key_material_and_original_nonempty_aad_are_unchanged() {
    let v = vector();
    let recipient = P256RecipientKey::generate_with_rng(&mut Fixed(bytes(&v["ikmR"]))).unwrap();
    assert_eq!(recipient.private_key(), bytes(&v["skRm"]));
    assert_eq!(recipient.public_key().as_slice(), bytes(&v["pkRm"]));
    let private = <Kem as KemTrait>::PrivateKey::from_bytes(recipient.private_key()).unwrap();
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&bytes(&v["enc"])).unwrap();
    let mut context =
        hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &private, &enc, &bytes(&v["info"]))
            .unwrap();
    let plaintext = context
        .open(
            &bytes(&v["encryption"]["ct"]),
            &bytes(&v["encryption"]["aad"]),
        )
        .unwrap();
    assert_eq!(plaintext, bytes(&v["encryption"]["pt"]));
    let (_, public) = Kem::derive_keypair(&bytes(&v["ikmE"]));
    assert_eq!(public.to_bytes().as_slice(), bytes(&v["enc"]));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn empty_aad_profile_matches_independent_ciphertext_and_exact_enc() {
    let v = vector();
    let recipient = P256RecipientKey::import(&bytes(&v["skRm"])).unwrap();
    let sealed = seal_with_rng(
        recipient.public_key(),
        &bytes(&v["info"]),
        &bytes(&v["encryption"]["pt"]),
        &mut Fixed(bytes(&v["ikmE"])),
    )
    .unwrap();
    assert_eq!(sealed.enc.as_slice(), bytes(&v["enc"]));
    assert_eq!(sealed.ciphertext, bytes(&v["empty_aad_ciphertext"]));
    let plaintext = open(
        &recipient,
        &sealed.enc,
        &bytes(&v["info"]),
        &sealed.ciphertext,
    )
    .unwrap();
    assert_eq!(plaintext.as_slice(), bytes(&v["encryption"]["pt"]));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authentication_rejects_changed_context_key_enc_ciphertext_and_tag() {
    let v = vector();
    let recipient = P256RecipientKey::import(&bytes(&v["skRm"])).unwrap();
    let enc = bytes(&v["enc"]);
    let ct = bytes(&v["empty_aad_ciphertext"]);
    let info = bytes(&v["info"]);
    let failed = |result: Result<_, _>| {
        assert!(matches!(
            result,
            Err(P256BaseError::PRIMITIVE_AUTHENTICATION_FAILED)
        ))
    };
    let mut changed = info.clone();
    changed.push(0);
    failed(open(&recipient, &enc, &changed, &ct));
    failed(open(
        &recipient,
        &enc,
        &info,
        &bytes(&v["encryption"]["ct"]),
    ));
    for position in [0, ct.len() - 1] {
        let mut changed = ct.clone();
        changed[position] ^= 1;
        failed(open(&recipient, &enc, &info, &changed));
    }
    let other = P256RecipientKey::generate_with_rng(&mut Fixed(vec![42; PRIVATE_KEY_LEN])).unwrap();
    failed(open(&other, &enc, &info, &ct));
    failed(open(&recipient, other.public_key(), &info, &ct));
    // A destroyed owner cannot be reused as an all-zero private scalar.
    let mut destroyed = recipient;
    destroyed.zeroize();
    assert!(matches!(
        open(&destroyed, &enc, &info, &ct),
        Err(P256BaseError::PRIMITIVE_INVALID_PRIVATE_KEY)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_points_keys_lengths_and_bounds_fail_closed() {
    let v = vector();
    let recipient = P256RecipientKey::import(&bytes(&v["skRm"])).unwrap();
    for key in [
        vec![],
        vec![1; 31],
        vec![0; 32],
        vec![0xff; 32],
        vec![1; 33],
    ] {
        assert!(matches!(
            P256RecipientKey::import(&key),
            Err(P256BaseError::PRIMITIVE_INVALID_PRIVATE_KEY)
        ));
    }
    for point in [
        vec![],
        vec![0; 65],
        vec![4; 65],
        vec![2; 33],
        vec![6; 65],
        vec![4; 66],
    ] {
        assert!(matches!(
            open(&recipient, &point, &[], &[0; 16]),
            Err(P256BaseError::PRIMITIVE_MALFORMED_CIPHERTEXT)
        ));
        assert!(matches!(
            seal_with_rng(&point, &[], &[], &mut Fails),
            Err(P256BaseError::PRIMITIVE_INVALID_PUBLIC_KEY)
        ));
    }
    assert!(matches!(
        open(&recipient, recipient.public_key(), &[], &[0; 15]),
        Err(P256BaseError::PRIMITIVE_MALFORMED_CIPHERTEXT)
    ));
    let excessive_info = vec![0; INFO_MAX_LEN + 1];
    assert!(matches!(
        seal_with_rng(recipient.public_key(), &excessive_info, &[], &mut Fails),
        Err(P256BaseError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    ));
    let excessive_message = vec![0; PLAINTEXT_MAX_LEN + 1];
    assert!(matches!(
        seal_with_rng(recipient.public_key(), &[], &excessive_message, &mut Fails),
        Err(P256BaseError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    ));
    let excessive_ct = vec![0; PLAINTEXT_MAX_LEN + 17];
    assert!(matches!(
        open(&recipient, recipient.public_key(), &[], &excessive_ct),
        Err(P256BaseError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rng_failure_and_clearing_ownership_are_explicit() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<P256RecipientKey>();
    clearing::<super::P256BasePlaintext>();
    assert!(matches!(
        P256RecipientKey::generate_with_rng(&mut Fails),
        Err(P256BaseError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    ));
    let recipient = P256RecipientKey::import(&bytes(&vector()["skRm"])).unwrap();
    assert!(matches!(
        seal_with_rng(recipient.public_key(), &[], &[], &mut Fails),
        Err(P256BaseError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    ));
    let mut plaintext = super::P256BasePlaintext::new(zeroize::Zeroizing::new(vec![42; 3]));
    assert_eq!(plaintext.len(), 3);
    plaintext.zeroize();
    assert!(plaintext.as_slice().iter().all(|byte| *byte == 0));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn empty_records_and_binary_context_are_preserved() {
    let recipient = P256RecipientKey::generate().unwrap();
    for info in [b"".as_slice(), b"\0\xff\0\x80".as_slice()] {
        let sealed = super::seal(recipient.public_key(), info, &[]).unwrap();
        assert_eq!(sealed.ciphertext.len(), 16);
        assert!(open(&recipient, &sealed.enc, info, &sealed.ciphertext)
            .unwrap()
            .is_empty());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn profile_rejects_psk_mode_and_a_different_kdf() {
    let v = vector();
    let recipient = P256RecipientKey::import(&bytes(&v["skRm"])).unwrap();
    let info = bytes(&v["info"]);
    let plaintext = bytes(&v["encryption"]["pt"]);
    let psk_record = crate::seal_psk(&crate::HpkePskSealRequest {
        suite: crate::HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
        recipient_public_key: recipient.public_key(),
        info: &info,
        aad: &[],
        plaintext: &plaintext,
        psk: &[42; 32],
        psk_id: b"test PSK identity",
    })
    .unwrap();
    assert!(matches!(
        open(
            &recipient,
            &psk_record.encapsulated_key,
            &info,
            &psk_record.ciphertext
        ),
        Err(P256BaseError::PRIMITIVE_AUTHENTICATION_FAILED)
    ));
    let public = <Kem as KemTrait>::PublicKey::from_bytes(recipient.public_key()).unwrap();
    let entropy = bytes(&v["ikmE"]);
    let mut rng = crate::random::FixedRandomness::new(&entropy);
    let (enc, mut context) = hpke::setup_sender_with_rng::<Aead, hpke::kdf::HkdfSha512, Kem>(
        &hpke::OpModeS::Base,
        &public,
        &info,
        &mut rng,
    )
    .unwrap();
    let ciphertext = context.seal(&plaintext, &[]).unwrap();
    assert!(matches!(
        open(&recipient, enc.to_bytes().as_slice(), &info, &ciphertext),
        Err(P256BaseError::PRIMITIVE_AUTHENTICATION_FAILED)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn largest_context_is_accepted_without_crossing_the_engine_limit() {
    let recipient = P256RecipientKey::generate().unwrap();
    let info = vec![0x80; INFO_MAX_LEN];
    let sealed = super::seal(recipient.public_key(), &info, &[]).unwrap();
    assert!(open(&recipient, &sealed.enc, &info, &sealed.ciphertext)
        .unwrap()
        .is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn largest_record_authenticates_and_tampering_never_returns_plaintext() {
    let v = vector();
    let recipient = P256RecipientKey::import(&bytes(&v["skRm"])).unwrap();
    let plaintext = zeroize::Zeroizing::new(vec![0x42; PLAINTEXT_MAX_LEN]);
    let info = b"maximum accepted record";
    let mut sealed = seal_with_rng(
        recipient.public_key(),
        info,
        plaintext.as_slice(),
        &mut Fixed(bytes(&v["ikmE"])),
    )
    .unwrap();
    assert_eq!(sealed.ciphertext.len(), PLAINTEXT_MAX_LEN + super::TAG_LEN);
    assert_eq!(
        open(&recipient, &sealed.enc, info, &sealed.ciphertext)
            .unwrap()
            .as_slice(),
        plaintext.as_slice()
    );
    *sealed.ciphertext.last_mut().unwrap() ^= 1;
    assert!(matches!(
        open(&recipient, &sealed.enc, info, &sealed.ciphertext),
        Err(P256BaseError::PRIMITIVE_AUTHENTICATION_FAILED)
    ));
}
