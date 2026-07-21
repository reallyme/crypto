// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Registered secp256k1 and RFC 9180 X448 DHKEM known-answer tests.

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(all(feature = "native", feature = "test-vectors"))]

use crypto_hpke::{
    derive_keypair, open_base, seal_base_derand, HpkeAeadId, HpkeDerandSealRequest, HpkeKdfId,
    HpkeKemId, HpkeOpenRequest, HpkeSuite,
};

fn decode(encoded: &str) -> Vec<u8> {
    hex::decode(encoded).expect("published vector must contain valid hexadecimal")
}

#[test]
fn secp256k1_aes256gcm_matches_registered_dhkem_vector() {
    // draft-wahby-cfrg-hpke-kem-secp256k1-01, Appendix B.2.1.
    let suite = HpkeSuite::new(
        HpkeKemId::DhKemSecp256k1HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes256Gcm,
    );
    let recipient_ikm = decode("323c89b1ca03ca9c4ac6316d02f4604f2f6804665a13d8635786281f00f18006");
    let expected_private_key =
        decode("024be5fda9036a2d81f8c634193b5ce83e65bfc4373ae8b7a960fea8770d1f8f");
    let expected_public_key = decode(concat!(
        "040986ec455812ddd870414c2753f75dadaefda155bc7bd18c4ab6ff3dd61b2e",
        "a3bee4ab2a0160b8e330757fc6d81d88ece7051bd9a07fa7e5368ea579e2e6c0e6"
    ));
    let ephemeral_ikm = decode("41233637379f346f4e70e9ca44c31e7ee284d42a5bfd72572ae8884a09aa355e");
    let expected_encapsulation = decode(concat!(
        "040de7712da136d40779452a32e70ec834fa092ee8e3f26450786c6cd51396e8",
        "596c958065594d30432e812fc7a53a10d7fce2ce9bf52ccce72cbad4c79d3b17f6"
    ));
    let expected_ciphertext = decode(concat!(
        "c90301b039fbe558e60316ab9e4f0396b90b1787e81a091c2afecb4ff563941",
        "442c07e9479c295b53954547640"
    ));
    let info = decode("b546c00cece2e2ff0815eb0f8124fb9028c66e80");
    let aad = decode("436f756e742d30");
    let plaintext = decode("4265617574792069732074727574682c20747275746820626561757479");

    let recipient = derive_keypair(suite, &recipient_ikm).expect("vector derivation succeeds");
    assert_eq!(recipient.private_key(), expected_private_key);
    assert_eq!(recipient.public_key, expected_public_key);

    let sealed = seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: &ephemeral_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("vector sealing succeeds");
    assert_eq!(sealed.encapsulated_key, expected_encapsulation);
    assert_eq!(sealed.ciphertext, expected_ciphertext);

    let opened = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: &info,
        aad: &aad,
        ciphertext: &sealed.ciphertext,
    })
    .expect("vector opening succeeds");
    assert_eq!(opened.plaintext.as_slice(), plaintext);
}

#[test]
fn x448_aes256gcm_matches_rfc9180_vector() {
    // RFC 9180 Appendix A, mode 0, KEM 0x0021, KDF 0x0003, AEAD 0x0002.
    let suite = HpkeSuite::new(
        HpkeKemId::DhKemX448HkdfSha512,
        HpkeKdfId::HkdfSha512,
        HpkeAeadId::Aes256Gcm,
    );
    let recipient_ikm = decode(concat!(
        "93e714430d3cb00e8e8a03dd820dcbcc7f0141f93c63a7dede2dfb15",
        "2b5b23982a1a55f2d86dd9e0f5a0f53b9c21605257ec1349d7f89e53"
    ));
    let expected_private_key = decode(concat!(
        "c4e72a57af1640806c01617b947ee6d1bbe5eb1a5b4616fb705a5d2e",
        "d30b7f4317365c504249750e090805d44a2ddc2970172414a90a09e5"
    ));
    let expected_public_key = decode(concat!(
        "d920db89afdb25df110a44cf0d7dc4e4d4b74f09ceaba5e76a12d3ca",
        "fefcd962e244804a58bfd12303732be21d511f877ddc2ed694447b3d"
    ));
    let ephemeral_ikm = decode(concat!(
        "39ed47496020ec7c2afc214425fc6a15fb6f1e16759c2b066265b6624",
        "c84ed50ee6c3129d9ed71318b19a96e5c5cc6b27aca5e1ae9cdc7e0"
    ));
    let expected_encapsulation = decode(concat!(
        "390f2971ca97d513915a2bc5aac0cb81b832d9424d2264eaa9e868d8",
        "0862edd7918276883a8d0434309e049408fec2340ae5799702f948d7"
    ));
    let expected_ciphertext = decode(concat!(
        "6a5ef0f8c88a17c6d26bee63b4468cd43360eb69804fb392d8c9b8eb",
        "a2f9bd806726c7d99cb9073022000ce41a"
    ));
    let info = decode("4f6465206f6e2061204772656369616e2055726e");
    let aad = decode("436f756e742d30");
    let plaintext = decode("4265617574792069732074727574682c20747275746820626561757479");

    let recipient = derive_keypair(suite, &recipient_ikm).expect("vector derivation succeeds");
    assert_eq!(recipient.private_key(), expected_private_key);
    assert_eq!(recipient.public_key, expected_public_key);

    let sealed = seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: &ephemeral_ikm,
        info: &info,
        aad: &aad,
        plaintext: &plaintext,
    })
    .expect("vector sealing succeeds");
    assert_eq!(sealed.encapsulated_key, expected_encapsulation);
    assert_eq!(sealed.ciphertext, expected_ciphertext);

    let opened = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: &info,
        aad: &aad,
        ciphertext: &sealed.ciphertext,
    })
    .expect("vector opening succeeds");
    assert_eq!(opened.plaintext.as_slice(), plaintext);
}
