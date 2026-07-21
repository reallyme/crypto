// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! OpenMLS adapter-contract and compatibility coverage.
//!
//! The named X-Wing/libcrux regression is the external interoperability anchor
//! in this module. The remaining tests exercise ReallyMe's adapter contract and
//! must not be treated as independent implementation vectors.

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_hpke::{
    derive_keypair_from_ikm, setup_receiver_psk, setup_sender_psk, HpkeError, HpkePskIdRef,
    HpkePskReceiverSetupRequest, HpkePskRef, HpkePskSenderContext, HpkePskSenderSetupRequest,
    HpkeReceiverContext, HpkeSuite, HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
    MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384, MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
    MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
};
use hpke::kem::{MlKem1024, MlKem1024P384};
use hpke::{Kem as HpkeKem, Serializable};
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

const IKM: &[u8] = b"openmls arbitrary-length epoch secret";
const INFO: &[u8] = b"openmls-targeted-message";
const AAD: &[u8] = b"openmls-targeted-message-aad";
const PSK: [u8; 32] = [0x6d; 32];
const PSK_ID: &[u8] = b"openmls-targeted-message-psk";
const PLAINTEXT: &[u8] = b"targeted message payload";
const XWING_OPENMLS_IKM: &[u8] = b"reallyme-openmls-xwing-key-derivation-input";
const XWING_OPENMLS_PRIVATE_KEY_HEX: &str =
    "52ae3a0dd250e72c72648e90e70fd085ee1a404331d49f99d7f868cd1f9d7f5e";
const XWING_OPENMLS_PUBLIC_KEY_SHA256_HEX: &str =
    "f8125a347a83ac4a18ffdeb3cbb788438d147558a8ec3ad9d4c9e1b4b592063d";

#[test]
fn arbitrary_ikm_uses_each_kems_registered_derive_key_pair() {
    let mlkem = derive_keypair_from_ikm(MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87, IKM)
        .expect("ML-KEM derivation succeeds");
    let (_, expected_mlkem_public_key) = MlKem1024::derive_keypair(IKM);
    assert_eq!(
        mlkem.public_key,
        expected_mlkem_public_key.to_bytes().as_slice()
    );

    let hybrid = derive_keypair_from_ikm(MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384, IKM)
        .expect("hybrid derivation succeeds");
    let (_, expected_hybrid_public_key) = MlKem1024P384::derive_keypair(IKM);
    assert_eq!(
        hybrid.public_key,
        expected_hybrid_public_key.to_bytes().as_slice()
    );
}

#[test]
fn arbitrary_ikm_derivation_is_stable_and_rejects_empty_input() {
    for suite in mls_profiles() {
        let first = derive_keypair_from_ikm(suite, IKM).expect("first derivation succeeds");
        let second = derive_keypair_from_ikm(suite, IKM).expect("second derivation succeeds");
        assert_eq!(first.public_key, second.public_key);
        assert_eq!(first.private_key(), second.private_key());
        assert_eq!(
            first.public_key.len(),
            suite.public_key_len().expect("suite is executable")
        );
        assert_eq!(
            first.private_key().len(),
            suite.private_key_len().expect("suite is executable")
        );
        assert_eq!(
            derive_keypair_from_ikm(suite, &[]).err(),
            Some(HpkeError::InvalidInputKeyMaterial)
        );
    }
}

#[test]
fn xwing_arbitrary_ikm_matches_the_deployed_openmls_libcrux_vector() {
    // These values are frozen from the OpenMLS ReallyMe-provider interop test,
    // which derives this keypair independently with the deployed libcrux
    // X-Wing draft-06 provider. The public-key fingerprint covers every byte
    // while keeping the regression vector compact enough to audit in source.
    let keypair =
        derive_keypair_from_ikm(HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305, XWING_OPENMLS_IKM)
            .expect("X-Wing derivation succeeds");
    let expected_private_key =
        hex::decode(XWING_OPENMLS_PRIVATE_KEY_HEX).expect("private-key vector is valid hex");

    assert_eq!(keypair.private_key(), expected_private_key.as_slice());
    assert_eq!(
        hex::encode(Sha256::digest(&keypair.public_key)),
        XWING_OPENMLS_PUBLIC_KEY_SHA256_HEX
    );
}

#[test]
fn split_psk_sender_setup_supports_targeted_message_aad() {
    assert_zeroize_on_drop::<HpkePskSenderContext>();
    assert_zeroize_on_drop::<HpkeReceiverContext>();

    for suite in mls_profiles() {
        let recipient = derive_keypair_from_ikm(suite, IKM).expect("recipient derivation succeeds");
        let mut sender = setup_sender_psk(&HpkePskSenderSetupRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            info: INFO,
            psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
            psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
        })
        .expect("sender setup succeeds");

        let mut aad = b"openmls-targeted-message-aad/".to_vec();
        aad.extend_from_slice(&sender.encapsulated_key);
        let ciphertext = sender
            .context
            .seal(&aad, PLAINTEXT)
            .expect("context sealing succeeds");
        let mut receiver = setup_receiver_psk(&HpkePskReceiverSetupRequest {
            suite,
            encapsulated_key: &sender.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
            psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
        })
        .expect("receiver setup succeeds");
        let opened = receiver
            .open(&aad, &ciphertext)
            .expect("receiver context opens targeted message");
        assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
    }
}

#[test]
fn split_psk_sender_setup_rejects_invalid_inputs_before_backend_setup() {
    let suite = MLS_192_MLKEM1024_AES256GCM_SHA384_P384;
    let short_psk = [0x41; 31];
    let short_psk_error = HpkePskRef::new(&short_psk).err();
    assert_eq!(short_psk_error, Some(HpkeError::InvalidPsk));

    let malformed_key = [0_u8; 8];
    let malformed_key_error = setup_sender_psk(&HpkePskSenderSetupRequest {
        suite,
        recipient_public_key: &malformed_key,
        info: INFO,
        psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
        psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
    })
    .err();
    assert_eq!(malformed_key_error, Some(HpkeError::InvalidPublicKey));

    let empty_psk_id_error = HpkePskIdRef::new(&[]).err();
    assert_eq!(empty_psk_id_error, Some(HpkeError::InvalidPskIdentifier));
}

#[test]
fn split_psk_receiver_rejects_malformed_setup_and_tampered_ciphertext() {
    let suite = MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
    let recipient = derive_keypair_from_ikm(suite, IKM).expect("recipient derivation succeeds");
    let mut sender = setup_sender_psk(&HpkePskSenderSetupRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        info: INFO,
        psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
        psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
    })
    .expect("sender setup succeeds");
    let ciphertext = sender
        .context
        .seal(AAD, PLAINTEXT)
        .expect("context sealing succeeds");

    let malformed_encapsulated_key = [0_u8; 1];
    let malformed_encapsulated_key_error = setup_receiver_psk(&HpkePskReceiverSetupRequest {
        suite,
        encapsulated_key: &malformed_encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: INFO,
        psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
        psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
    })
    .err();
    assert_eq!(
        malformed_encapsulated_key_error,
        Some(HpkeError::InvalidEncapsulatedKey)
    );

    let malformed_private_key = [0_u8; 1];
    let malformed_private_key_error = setup_receiver_psk(&HpkePskReceiverSetupRequest {
        suite,
        encapsulated_key: &sender.encapsulated_key,
        recipient_private_key: &malformed_private_key,
        info: INFO,
        psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
        psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
    })
    .err();
    assert_eq!(
        malformed_private_key_error,
        Some(HpkeError::InvalidPrivateKey)
    );

    let mut receiver = setup_receiver_psk(&HpkePskReceiverSetupRequest {
        suite,
        encapsulated_key: &sender.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: INFO,
        psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
        psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
    })
    .expect("receiver setup succeeds");
    let mut tampered_ciphertext = ciphertext;
    if let Some(first) = tampered_ciphertext.first_mut() {
        *first ^= 0x80;
    }
    assert_eq!(
        receiver.open(AAD, &tampered_ciphertext).err(),
        Some(HpkeError::OpenFailed)
    );
}

fn mls_profiles() -> [HpkeSuite; 3] {
    [
        MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
    ]
}

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
