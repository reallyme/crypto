// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Deterministic regression coverage for the OpenMLS-facing HPKE profiles.
//!
//! These vectors are produced and consumed by the ReallyMe HPKE backend. They
//! prove deterministic API behavior and profile coverage, but deliberately do
//! not claim independent cross-implementation provenance.

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(all(feature = "native", feature = "test-vectors"))]

use crypto_hpke::{
    derive_keypair_from_ikm, open_base, open_psk, receiver_export, seal_base_derand,
    sender_export_derand, setup_sender_psk_derand, HpkeDerandPskSenderSetupRequest,
    HpkeDerandSealRequest, HpkeDerandSenderExportRequest, HpkeError, HpkeOpenRequest, HpkePskIdRef,
    HpkePskOpenRequest, HpkePskRef, HpkeReceiverExportRequest, HpkeSuite,
    MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384, MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
    MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
};

const IKM: &[u8] = b"fixed OpenMLS vector IKM";
const INFO: &[u8] = b"fixed OpenMLS vector info";
const AAD: &[u8] = b"fixed OpenMLS vector aad";
const PLAINTEXT: &[u8] = b"fixed OpenMLS vector plaintext";
const PSK: [u8; 32] = [0x91; 32];
const PSK_ID: &[u8] = b"fixed-openmls-vector-psk";

#[test]
fn all_mls_profiles_support_deterministic_base_seal() {
    for suite in mls_profiles() {
        let recipient = derive_keypair_from_ikm(suite, IKM).expect("recipient derivation succeeds");
        let randomness = vec![
            0x39;
            suite
                .encapsulation_randomness_len()
                .expect("suite is executable")
        ];
        let request = HpkeDerandSealRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            encapsulation_randomness: &randomness,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
        };
        let first = seal_base_derand(&request).expect("first deterministic seal succeeds");
        let second = seal_base_derand(&request).expect("second deterministic seal succeeds");
        assert_eq!(first.encapsulated_key, second.encapsulated_key);
        assert_eq!(first.ciphertext, second.ciphertext);

        let opened = open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &first.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &first.ciphertext,
        })
        .expect("deterministic ciphertext opens");
        assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
    }
}

#[test]
fn all_mls_profiles_support_deterministic_split_psk_setup() {
    for suite in mls_profiles() {
        let recipient = derive_keypair_from_ikm(suite, IKM).expect("recipient derivation succeeds");
        let randomness = vec![
            0x72;
            suite
                .encapsulation_randomness_len()
                .expect("suite is executable")
        ];
        let request = HpkeDerandPskSenderSetupRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            encapsulation_randomness: &randomness,
            info: INFO,
            psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
            psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
        };
        let mut first =
            setup_sender_psk_derand(&request).expect("first deterministic setup succeeds");
        let mut second =
            setup_sender_psk_derand(&request).expect("second deterministic setup succeeds");
        assert_eq!(first.encapsulated_key, second.encapsulated_key);

        let mut aad = AAD.to_vec();
        aad.extend_from_slice(&first.encapsulated_key);
        let first_ciphertext = first
            .context
            .seal(&aad, PLAINTEXT)
            .expect("first context seal succeeds");
        let second_ciphertext = second
            .context
            .seal(&aad, PLAINTEXT)
            .expect("second context seal succeeds");
        assert_eq!(first_ciphertext, second_ciphertext);

        let opened = open_psk(&HpkePskOpenRequest {
            suite,
            encapsulated_key: &first.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            aad: &aad,
            ciphertext: &first_ciphertext,
            psk: &PSK,
            psk_id: PSK_ID,
        })
        .expect("deterministic PSK ciphertext opens");
        assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
    }
}

#[test]
fn all_mls_profiles_support_deterministic_sender_export() {
    for suite in mls_profiles() {
        let recipient = derive_keypair_from_ikm(suite, IKM).expect("recipient derivation succeeds");
        let randomness = vec![
            0x54;
            suite
                .encapsulation_randomness_len()
                .expect("suite is executable")
        ];
        let request = HpkeDerandSenderExportRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            encapsulation_randomness: &randomness,
            info: INFO,
            exporter_context: b"fixed OpenMLS exporter context",
            output_length: 48,
        };
        let first = sender_export_derand(&request).expect("first deterministic export succeeds");
        let second = sender_export_derand(&request).expect("second deterministic export succeeds");
        assert_eq!(first.encapsulated_key, second.encapsulated_key);
        assert_eq!(first.exporter_secret(), second.exporter_secret());

        let receiver = receiver_export(&HpkeReceiverExportRequest {
            suite,
            encapsulated_key: &first.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            exporter_context: b"fixed OpenMLS exporter context",
            output_length: 48,
        })
        .expect("receiver export succeeds");
        assert_eq!(first.exporter_secret(), receiver.as_slice());
    }
}

#[test]
fn deterministic_split_setup_rejects_wrong_randomness_lengths() {
    for suite in mls_profiles() {
        let recipient = derive_keypair_from_ikm(suite, IKM).expect("recipient derivation succeeds");
        let randomness = [0x18; 1];
        let error = setup_sender_psk_derand(&HpkeDerandPskSenderSetupRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            encapsulation_randomness: &randomness,
            info: INFO,
            psk: HpkePskRef::new(&PSK).expect("PSK is valid"),
            psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
        })
        .err();
        assert_eq!(error, Some(HpkeError::InvalidRandomness));
    }
}

fn mls_profiles() -> [HpkeSuite; 3] {
    [
        MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
    ]
}
