// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(feature = "native")]

use crypto_hpke::{
    derive_keypair, open_base, open_psk, receiver_export, seal_base, seal_psk, sender_export,
    setup_receiver_psk, setup_sender_psk, HpkeAeadId, HpkeError, HpkeKdfId, HpkeKemId,
    HpkeOpenRequest, HpkePskIdRef, HpkePskOpenRequest, HpkePskReceiverSetupRequest, HpkePskRef,
    HpkePskSealRequest, HpkePskSenderSetupRequest, HpkeReceiverExportRequest, HpkeSealRequest,
    HpkeSenderExportRequest, HpkeSuite,
};
use zeroize::Zeroizing;

const INFO: &[u8] = b"reallyme/hpke-low-order/v1";
const AAD: &[u8] = b"bound metadata";
const PLAINTEXT: &[u8] = b"secret payload";
const PSK_ID: &[u8] = b"shared-key-id";
const EXPORTER_CONTEXT: &[u8] = b"application key";
const EXPORT_LENGTH: usize = 32;

fn suite(kem: HpkeKemId) -> HpkeSuite {
    let kdf = match kem {
        HpkeKemId::DhKemX448HkdfSha512 => HpkeKdfId::HkdfSha512,
        _ => HpkeKdfId::HkdfSha256,
    };
    HpkeSuite::new(kem, kdf, HpkeAeadId::Aes256Gcm)
}

#[test]
fn x25519_low_order_encodings_have_consistent_errors() -> Result<(), HpkeError> {
    let suite = suite(HpkeKemId::DhKemX25519HkdfSha256);
    // All low-order coordinates, including p and p+1. RFC 7748 also masks
    // the top bit, so exercise both encodings for every coordinate.
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let mut key = hex::decode(encoded).map_err(|_| HpkeError::BACKEND_INTERNAL)?;
        assert_rejected_by_all_routes(suite, &key)?;
        let last_byte = key.last_mut().ok_or(HpkeError::BACKEND_INTERNAL)?;
        *last_byte |= 0x80;
        assert_rejected_by_all_routes(suite, &key)?;
    }
    Ok(())
}

#[test]
fn x448_low_order_encodings_have_consistent_errors() -> Result<(), HpkeError> {
    let suite = suite(HpkeKemId::DhKemX448HkdfSha512);
    let mut one = [0_u8; 56];
    one[0] = 1;
    let mut prime = [0xff; 56];
    prime[28] = 0xfe;
    let mut minus_one = prime;
    minus_one[0] = 0xfe;
    let mut prime_plus_one = [0xff; 56];
    prime_plus_one[..28].fill(0);
    for key in [[0; 56], one, minus_one, prime, prime_plus_one] {
        assert_rejected_by_all_routes(suite, &key)?;
    }
    Ok(())
}

fn assert_rejected_by_all_routes(suite: HpkeSuite, key: &[u8]) -> Result<(), HpkeError> {
    let psk = Zeroizing::new([0x47; 32]);
    let seed = Zeroizing::new(vec![0x73; suite.private_key_len()?]);
    let recipient = derive_keypair(suite, &seed)?;
    let invalid_public_key = Some(HpkeError::PRIMITIVE_INVALID_PUBLIC_KEY);
    let malformed_encapsulated_key = Some(HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT);
    assert_eq!(
        seal_base(&HpkeSealRequest {
            suite,
            recipient_public_key: key,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
        })
        .err(),
        invalid_public_key,
    );
    assert_eq!(
        seal_psk(&HpkePskSealRequest {
            suite,
            recipient_public_key: key,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
            psk: psk.as_slice(),
            psk_id: PSK_ID,
        })
        .err(),
        invalid_public_key,
    );
    assert_eq!(
        setup_sender_psk(&HpkePskSenderSetupRequest {
            suite,
            recipient_public_key: key,
            info: INFO,
            psk: HpkePskRef::new(psk.as_slice())?,
            psk_id: HpkePskIdRef::new(PSK_ID)?,
        })
        .err(),
        invalid_public_key,
    );
    assert_eq!(
        open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &[0; 16],
        })
        .err(),
        malformed_encapsulated_key,
    );
    assert_eq!(
        open_psk(&HpkePskOpenRequest {
            suite,
            encapsulated_key: key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &[0; 16],
            psk: psk.as_slice(),
            psk_id: PSK_ID,
        })
        .err(),
        malformed_encapsulated_key,
    );
    assert_eq!(
        setup_receiver_psk(&HpkePskReceiverSetupRequest {
            suite,
            encapsulated_key: key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            psk: HpkePskRef::new(psk.as_slice())?,
            psk_id: HpkePskIdRef::new(PSK_ID)?,
        })
        .err(),
        malformed_encapsulated_key,
    );
    // Exporters support both ordinary AEAD suites and export-only suites;
    // neither may turn a rejected peer key into a backend failure.
    for aead in [suite.aead, HpkeAeadId::ExportOnly] {
        let suite = HpkeSuite::new(suite.kem, suite.kdf, aead);
        assert_eq!(
            sender_export(&HpkeSenderExportRequest {
                suite,
                recipient_public_key: key,
                info: INFO,
                exporter_context: EXPORTER_CONTEXT,
                output_length: EXPORT_LENGTH,
            })
            .err(),
            invalid_public_key,
        );
        assert_eq!(
            receiver_export(&HpkeReceiverExportRequest {
                suite,
                encapsulated_key: key,
                recipient_private_key: recipient.private_key(),
                info: INFO,
                exporter_context: EXPORTER_CONTEXT,
                output_length: EXPORT_LENGTH,
            })
            .err(),
            malformed_encapsulated_key,
        );
    }
    Ok(())
}

#[test]
fn valid_keys_still_agree_in_every_mode() -> Result<(), HpkeError> {
    for kem in [
        HpkeKemId::DhKemX25519HkdfSha256,
        HpkeKemId::DhKemX448HkdfSha512,
    ] {
        let suite = suite(kem);
        let seed = Zeroizing::new(vec![0x73; suite.private_key_len()?]);
        let recipient = derive_keypair(suite, &seed)?;
        let psk = Zeroizing::new([0x47; 32]);
        let mut sender = setup_sender_psk(&HpkePskSenderSetupRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            info: INFO,
            psk: HpkePskRef::new(psk.as_slice())?,
            psk_id: HpkePskIdRef::new(PSK_ID)?,
        })?;
        let ciphertext = sender.context.seal(AAD, PLAINTEXT)?;
        let mut receiver = setup_receiver_psk(&HpkePskReceiverSetupRequest {
            suite,
            encapsulated_key: &sender.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            psk: HpkePskRef::new(psk.as_slice())?,
            psk_id: HpkePskIdRef::new(PSK_ID)?,
        })?;
        assert_eq!(
            receiver.open(AAD, &ciphertext)?.plaintext.as_slice(),
            PLAINTEXT
        );
        let sender = sender_export(&HpkeSenderExportRequest {
            suite,
            recipient_public_key: &recipient.public_key,
            info: INFO,
            exporter_context: EXPORTER_CONTEXT,
            output_length: EXPORT_LENGTH,
        })?;
        let receiver = receiver_export(&HpkeReceiverExportRequest {
            suite,
            encapsulated_key: &sender.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            exporter_context: EXPORTER_CONTEXT,
            output_length: EXPORT_LENGTH,
        })?;
        assert_eq!(sender.exporter_secret(), receiver.as_slice());
    }
    Ok(())
}
