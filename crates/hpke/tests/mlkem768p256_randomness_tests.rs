// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(all(feature = "native", feature = "test-vectors"))]

use crypto_hpke::{
    derive_keypair, open_base, receiver_export, seal_base, seal_base_derand, sender_export,
    sender_export_derand, setup_receiver_psk, setup_sender_psk, setup_sender_psk_derand,
    HpkeDerandPskSenderSetupRequest, HpkeDerandSealRequest, HpkeDerandSenderExportRequest,
    HpkeError, HpkeKeyPair, HpkeOpenRequest, HpkePskIdRef, HpkePskReceiverSetupRequest, HpkePskRef,
    HpkePskSenderSetupRequest, HpkeReceiverExportRequest, HpkeSealRequest, HpkeSenderExportRequest,
    HPKE_MLKEM768P256_SHAKE256_AES256GCM,
};
use zeroize::Zeroizing;

const RANDOMNESS_LEN: usize = 160;
const SCALAR_LEN: usize = 32;
const INFO: &[u8] = b"hybrid HPKE randomness contract";
const AAD: &[u8] = b"hybrid aad";
const PLAINTEXT: &[u8] = b"hybrid plaintext";
const PSK: [u8; 32] = [0x59; 32];
const PSK_ID: &[u8] = b"hybrid psk";
const EXPORTER_CONTEXT: &[u8] = b"hybrid exporter";
const EXPORT_LEN: usize = 32;

fn recipient() -> Result<HpkeKeyPair, HpkeError> {
    let ikm = Zeroizing::new([0x43; 32]);
    derive_keypair(HPKE_MLKEM768P256_SHAKE256_AES256GCM, ikm.as_slice())
}

#[test]
fn fixed_width_randomness_works_for_all_sender_routes() -> Result<(), HpkeError> {
    let suite = HPKE_MLKEM768P256_SHAKE256_AES256GCM;
    assert_eq!(suite.encapsulation_randomness_len()?, RANDOMNESS_LEN);
    let recipient = recipient()?;
    let randomness = Zeroizing::new([0x27; RANDOMNESS_LEN]);
    let deterministic = seal_base_derand(&seal_request(&recipient, randomness.as_slice()))?;
    let random = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })?;
    for sealed in [deterministic, random] {
        let opened = open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &sealed.ciphertext,
        })?;
        assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
    }

    let deterministic = sender_export_derand(&export_request(&recipient, randomness.as_slice()))?;
    let random = sender_export(&HpkeSenderExportRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: EXPORT_LEN,
    })?;
    for sender in [deterministic, random] {
        let receiver = receiver_export(&HpkeReceiverExportRequest {
            suite,
            encapsulated_key: &sender.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            exporter_context: EXPORTER_CONTEXT,
            output_length: EXPORT_LEN,
        })?;
        assert_eq!(receiver.as_slice(), sender.exporter_secret());
    }

    let deterministic = setup_sender_psk_derand(&psk_request(&recipient, randomness.as_slice())?)?;
    let random = setup_sender_psk(&HpkePskSenderSetupRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        info: INFO,
        psk: HpkePskRef::new(&PSK)?,
        psk_id: HpkePskIdRef::new(PSK_ID)?,
    })?;
    for mut sender in [deterministic, random] {
        let ciphertext = sender.context.seal(AAD, PLAINTEXT)?;
        let mut receiver = setup_receiver_psk(&HpkePskReceiverSetupRequest {
            suite,
            encapsulated_key: &sender.encapsulated_key,
            recipient_private_key: recipient.private_key(),
            info: INFO,
            psk: HpkePskRef::new(&PSK)?,
            psk_id: HpkePskIdRef::new(PSK_ID)?,
        })?;
        assert_eq!(
            receiver.open(AAD, &ciphertext)?.plaintext.as_slice(),
            PLAINTEXT
        );
    }
    Ok(())
}

#[test]
fn all_sender_routes_reject_incorrect_randomness_lengths() -> Result<(), HpkeError> {
    let recipient = recipient()?;
    for length in [0, 32, 64, 159, 161] {
        let randomness = Zeroizing::new(vec![0x27; length]);
        assert_sender_errors(
            &recipient,
            &randomness,
            HpkeError::PRIMITIVE_INVALID_PARAMETER,
        )?;
    }
    Ok(())
}

#[test]
fn scalar_sampling_uses_the_last_reserved_candidate_and_fails_on_exhaustion(
) -> Result<(), HpkeError> {
    let recipient = recipient()?;
    let mut randomness = Zeroizing::new([0xff; RANDOMNESS_LEN]);
    let final_scalar_offset = RANDOMNESS_LEN
        .checked_sub(SCALAR_LEN)
        .ok_or(HpkeError::PRIMITIVE_INVALID_LENGTH)?;
    randomness[final_scalar_offset..].fill(0x27);
    let sealed = seal_base_derand(&seal_request(&recipient, randomness.as_slice()))?;
    let opened = open_base(&HpkeOpenRequest {
        suite: HPKE_MLKEM768P256_SHAKE256_AES256GCM,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: INFO,
        aad: AAD,
        ciphertext: &sealed.ciphertext,
    })?;
    assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);

    // Four rejected candidates exhaust the bounded seed. The backend may
    // terminate its sampler with synthetic bytes, but no sender may use them.
    randomness[final_scalar_offset..].fill(0xff);
    assert_sender_errors(
        &recipient,
        randomness.as_slice(),
        HpkeError::BACKEND_INTERNAL,
    )
}

fn assert_sender_errors(
    recipient: &HpkeKeyPair,
    randomness: &[u8],
    expected: HpkeError,
) -> Result<(), HpkeError> {
    assert_eq!(
        seal_base_derand(&seal_request(recipient, randomness)).err(),
        Some(expected)
    );
    assert_eq!(
        sender_export_derand(&export_request(recipient, randomness)).err(),
        Some(expected)
    );
    assert_eq!(
        setup_sender_psk_derand(&psk_request(recipient, randomness)?).err(),
        Some(expected)
    );
    Ok(())
}

fn seal_request<'a>(recipient: &'a HpkeKeyPair, randomness: &'a [u8]) -> HpkeDerandSealRequest<'a> {
    HpkeDerandSealRequest {
        suite: HPKE_MLKEM768P256_SHAKE256_AES256GCM,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: randomness,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    }
}

fn export_request<'a>(
    recipient: &'a HpkeKeyPair,
    randomness: &'a [u8],
) -> HpkeDerandSenderExportRequest<'a> {
    HpkeDerandSenderExportRequest {
        suite: HPKE_MLKEM768P256_SHAKE256_AES256GCM,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: randomness,
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: EXPORT_LEN,
    }
}

fn psk_request<'a>(
    recipient: &'a HpkeKeyPair,
    randomness: &'a [u8],
) -> Result<HpkeDerandPskSenderSetupRequest<'a>, HpkeError> {
    Ok(HpkeDerandPskSenderSetupRequest {
        suite: HPKE_MLKEM768P256_SHAKE256_AES256GCM,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: randomness,
        info: INFO,
        psk: HpkePskRef::new(&PSK)?,
        psk_id: HpkePskIdRef::new(PSK_ID)?,
    })
}
