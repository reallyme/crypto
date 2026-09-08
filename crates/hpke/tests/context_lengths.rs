// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_hpke::{
    derive_keypair, open_base, open_psk, receiver_export, seal_base, seal_psk, sender_export,
    HpkeAeadId, HpkeError, HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkePskOpenRequest,
    HpkePskSealRequest, HpkeReceiverExportRequest, HpkeSealRequest, HpkeSenderExportRequest,
    HpkeSuite,
};
use zeroize::Zeroizing;

const PLAINTEXT: &[u8] = b"HPKE context length fixture";
const LARGE_CONTEXT_LEN: usize = 131_072;
const MAXIMUM_SHAKE_CONTEXT_LEN: usize = 65_530;

fn suite(kdf: HpkeKdfId) -> HpkeSuite {
    HpkeSuite::new(HpkeKemId::MlKem1024, kdf, HpkeAeadId::Aes256Gcm)
}

fn keypair(suite: HpkeSuite) -> crypto_hpke::HpkeKeyPair {
    let ikm = Zeroizing::new(vec![0x73; suite.private_key_len().expect("supported KEM")]);
    derive_keypair(suite, &ikm).expect("key derivation succeeds")
}

#[test]
fn hkdf_base_and_export_accept_large_contexts_and_authenticate_the_tail() {
    for kdf in [
        HpkeKdfId::HkdfSha256,
        HpkeKdfId::HkdfSha384,
        HpkeKdfId::HkdfSha512,
    ] {
        let suite = suite(kdf);
        let keypair = keypair(suite);
        for length in [MAXIMUM_SHAKE_CONTEXT_LEN, 65_531, LARGE_CONTEXT_LEN] {
            let mut info = vec![0x42; length];
            let sealed = seal_base(&HpkeSealRequest {
                suite,
                recipient_public_key: &keypair.public_key,
                info: &info,
                aad: &[],
                plaintext: PLAINTEXT,
            })
            .expect("HKDF accepts the complete context");
            let opened = open_base(&HpkeOpenRequest {
                suite,
                encapsulated_key: &sealed.encapsulated_key,
                recipient_private_key: keypair.private_key(),
                info: &info,
                aad: &[],
                ciphertext: &sealed.ciphertext,
            })
            .expect("large-context ciphertext opens");
            assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
            let sender = sender_export(&HpkeSenderExportRequest {
                suite,
                recipient_public_key: &keypair.public_key,
                info: &info,
                exporter_context: &info,
                output_length: 32,
            })
            .expect("large sender context exports");
            let receiver = receiver_export(&HpkeReceiverExportRequest {
                suite,
                encapsulated_key: &sender.encapsulated_key,
                recipient_private_key: keypair.private_key(),
                info: &info,
                exporter_context: &info,
                output_length: 32,
            })
            .expect("large receiver context exports");
            assert!(sender.exporter_secret() == receiver.as_slice());
            *info.last_mut().expect("nonempty context") ^= 1;
            assert_eq!(
                open_base(&HpkeOpenRequest {
                    suite,
                    encapsulated_key: &sealed.encapsulated_key,
                    recipient_private_key: keypair.private_key(),
                    info: &info,
                    aad: &[],
                    ciphertext: &sealed.ciphertext,
                })
                .err(),
                Some(HpkeError::OpenFailed)
            );
        }
    }
}

#[test]
fn hkdf_psk_mode_accepts_large_info_identifiers_and_keys() {
    let psk = Zeroizing::new(vec![0x5a; LARGE_CONTEXT_LEN]);
    let mut psk_id = vec![0x49; LARGE_CONTEXT_LEN];
    let info = vec![0x42; LARGE_CONTEXT_LEN];
    for kdf in [
        HpkeKdfId::HkdfSha256,
        HpkeKdfId::HkdfSha384,
        HpkeKdfId::HkdfSha512,
    ] {
        let suite = suite(kdf);
        let keypair = keypair(suite);
        let sealed = seal_psk(&HpkePskSealRequest {
            suite,
            recipient_public_key: &keypair.public_key,
            info: &info,
            aad: &[],
            plaintext: PLAINTEXT,
            psk: &psk,
            psk_id: &psk_id,
        })
        .expect("HKDF accepts large independently extracted inputs");
        let opened = open_psk(&HpkePskOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: keypair.private_key(),
            info: &info,
            aad: &[],
            ciphertext: &sealed.ciphertext,
            psk: &psk,
            psk_id: &psk_id,
        })
        .expect("large PSK context opens");
        assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
        *psk_id.last_mut().expect("nonempty identifier") ^= 1;
        assert_eq!(
            open_psk(&HpkePskOpenRequest {
                suite,
                encapsulated_key: &sealed.encapsulated_key,
                recipient_private_key: keypair.private_key(),
                info: &info,
                aad: &[],
                ciphertext: &sealed.ciphertext,
                psk: &psk,
                psk_id: &psk_id,
            })
            .err(),
            Some(HpkeError::OpenFailed)
        );
    }
}

#[test]
fn shake_retains_context_bounds_for_base_export_and_psk_modes() {
    let suite = suite(HpkeKdfId::Shake256);
    let keypair = keypair(suite);
    let mut info = vec![0x42; MAXIMUM_SHAKE_CONTEXT_LEN];
    let sealed = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: &info,
        aad: &[],
        plaintext: PLAINTEXT,
    })
    .expect("maximum SHAKE context seals");
    open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: &info,
        aad: &[],
        ciphertext: &sealed.ciphertext,
    })
    .expect("maximum SHAKE context opens");
    let sender = sender_export(&HpkeSenderExportRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: &info,
        exporter_context: &[],
        output_length: 32,
    })
    .expect("maximum SHAKE context exports");
    let receiver = receiver_export(&HpkeReceiverExportRequest {
        suite,
        encapsulated_key: &sender.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: &info,
        exporter_context: &[],
        output_length: 32,
    })
    .expect("maximum SHAKE receiver context exports");
    assert!(sender.exporter_secret() == receiver.as_slice());
    info.push(0);
    assert_eq!(
        seal_base(&HpkeSealRequest {
            suite,
            recipient_public_key: &keypair.public_key,
            info: &info,
            aad: &[],
            plaintext: PLAINTEXT,
        })
        .err(),
        Some(HpkeError::InvalidInfoLength)
    );
    assert_eq!(
        open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: keypair.private_key(),
            info: &info,
            aad: &[],
            ciphertext: &sealed.ciphertext,
        })
        .err(),
        Some(HpkeError::InvalidInfoLength)
    );
    assert_eq!(
        sender_export(&HpkeSenderExportRequest {
            suite,
            recipient_public_key: &keypair.public_key,
            info: &info,
            exporter_context: &[],
            output_length: 32,
        })
        .err(),
        Some(HpkeError::InvalidInfoLength)
    );
    assert_eq!(
        receiver_export(&HpkeReceiverExportRequest {
            suite,
            encapsulated_key: &sender.encapsulated_key,
            recipient_private_key: keypair.private_key(),
            info: &info,
            exporter_context: &[],
            output_length: 32,
        })
        .err(),
        Some(HpkeError::InvalidInfoLength)
    );
    // The PSK identifier shares the one-stage context budget with info.
    let psk = Zeroizing::new([0x5a; 32]);
    info.truncate(
        MAXIMUM_SHAKE_CONTEXT_LEN
            .checked_sub(1)
            .expect("nonzero bound"),
    );
    let sealed = seal_psk(&HpkePskSealRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: &info,
        aad: &[],
        plaintext: PLAINTEXT,
        psk: psk.as_slice(),
        psk_id: b"x",
    })
    .expect("maximum combined context seals");
    open_psk(&HpkePskOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: &info,
        aad: &[],
        ciphertext: &sealed.ciphertext,
        psk: psk.as_slice(),
        psk_id: b"x",
    })
    .expect("maximum combined context opens");
    for oversized_id in [&b"xx"[..], info.as_slice()] {
        assert_eq!(
            seal_psk(&HpkePskSealRequest {
                suite,
                recipient_public_key: &keypair.public_key,
                info: &info,
                aad: &[],
                plaintext: PLAINTEXT,
                psk: psk.as_slice(),
                psk_id: oversized_id,
            })
            .err(),
            Some(HpkeError::InvalidInfoLength)
        );
        assert_eq!(
            open_psk(&HpkePskOpenRequest {
                suite,
                encapsulated_key: &sealed.encapsulated_key,
                recipient_private_key: keypair.private_key(),
                info: &info,
                aad: &[],
                ciphertext: &sealed.ciphertext,
                psk: psk.as_slice(),
                psk_id: oversized_id,
            })
            .err(),
            Some(HpkeError::InvalidInfoLength)
        );
    }
}

#[test]
fn shake_rejects_oversized_psks_before_the_backend_can_panic() {
    let suite = suite(HpkeKdfId::Shake256);
    let keypair = keypair(suite);
    let mut psk = Zeroizing::new(vec![0x5a; usize::from(u16::MAX)]);
    let sealed = seal_psk(&HpkePskSealRequest {
        suite,
        recipient_public_key: &keypair.public_key,
        info: &[],
        aad: &[],
        plaintext: PLAINTEXT,
        psk: &psk,
        psk_id: b"x",
    })
    .expect("maximum encodable PSK seals");
    open_psk(&HpkePskOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: keypair.private_key(),
        info: &[],
        aad: &[],
        ciphertext: &sealed.ciphertext,
        psk: &psk,
        psk_id: b"x",
    })
    .expect("maximum encodable PSK opens");
    psk.push(0);
    assert_eq!(
        seal_psk(&HpkePskSealRequest {
            suite,
            recipient_public_key: &keypair.public_key,
            info: &[],
            aad: &[],
            plaintext: PLAINTEXT,
            psk: &psk,
            psk_id: b"x",
        })
        .err(),
        Some(HpkeError::InvalidPsk)
    );
    assert_eq!(
        open_psk(&HpkePskOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: keypair.private_key(),
            info: &[],
            aad: &[],
            ciphertext: &sealed.ciphertext,
            psk: &psk,
            psk_id: b"x",
        })
        .err(),
        Some(HpkeError::InvalidPsk)
    );
}
