// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_hpke::{
    derive_keypair, open_base, seal_base, HpkeAeadId, HpkeError, HpkeKdfId, HpkeKemId,
    HpkeOpenRequest, HpkeSealRequest, HpkeSuite,
};

const INFO: &[u8] = b"reallyme/dhkem-negative/v1";
const AAD: &[u8] = b"bound metadata";
const PLAINTEXT: &[u8] = b"secret payload";

fn secp256k1_suite() -> HpkeSuite {
    HpkeSuite::new(
        HpkeKemId::DhKemSecp256k1HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes256Gcm,
    )
}

fn x448_suite() -> HpkeSuite {
    HpkeSuite::new(
        HpkeKemId::DhKemX448HkdfSha512,
        HpkeKdfId::HkdfSha512,
        HpkeAeadId::Aes256Gcm,
    )
}

#[test]
fn secp256k1_rejects_compressed_and_off_curve_public_keys() {
    let compressed = [0x02_u8; 33];
    let off_curve = [0x04_u8; 65];

    for public_key in [compressed.as_slice(), off_curve.as_slice()] {
        let error = seal_base(&HpkeSealRequest {
            suite: secp256k1_suite(),
            recipient_public_key: public_key,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
        })
        .err()
        .expect("invalid secp256k1 public key must fail");
        assert_eq!(error, HpkeError::InvalidPublicKey);
    }
}

#[test]
fn x448_rejects_low_order_recipient_and_encapsulated_keys() {
    let suite = x448_suite();
    let low_order = [0_u8; 56];
    let seal_error = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &low_order,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .err()
    .expect("low-order X448 recipient key must fail");
    assert_eq!(seal_error, HpkeError::InvalidPublicKey);

    let recipient = derive_keypair(suite, &[0x73_u8; 56]).expect("recipient derivation succeeds");
    let open_error = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &low_order,
        recipient_private_key: recipient.private_key(),
        info: INFO,
        aad: AAD,
        ciphertext: &[0_u8; 16],
    })
    .err()
    .expect("low-order X448 encapsulated key must fail");
    assert_eq!(open_error, HpkeError::InvalidEncapsulatedKey);
}

#[test]
fn new_dhkems_reject_wrong_recipient_and_tampering() {
    for suite in [secp256k1_suite(), x448_suite()] {
        let recipient = derive_keypair(
            suite,
            &vec![0x73_u8; suite.private_key_len().expect("suite is executable")],
        )
        .expect("recipient derivation succeeds");
        let wrong_recipient = derive_keypair(
            suite,
            &vec![0x91_u8; suite.private_key_len().expect("suite is executable")],
        )
        .expect("wrong-recipient derivation succeeds");
        let sealed = seal_base(&HpkeSealRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
        })
        .expect("sealing succeeds");

        let wrong_key_error = open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: wrong_recipient.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &sealed.ciphertext,
        })
        .err()
        .expect("wrong recipient key must fail");
        assert_eq!(wrong_key_error, HpkeError::OpenFailed);

        let mut tampered = sealed.ciphertext;
        tampered[0] ^= 0x80;
        let tamper_error = open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &tampered,
        })
        .err()
        .expect("tampered ciphertext must fail");
        assert_eq!(tamper_error, HpkeError::OpenFailed);
    }
}
