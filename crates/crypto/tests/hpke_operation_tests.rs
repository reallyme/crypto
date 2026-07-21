// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic-owner coverage for all HPKE operations and error classes.

#![allow(clippy::expect_used)]

use reallyme_crypto::hpke::{
    HpkeAeadId, HpkeError, HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkePskIdRef, HpkePskOpenRequest,
    HpkePskReceiverSetupRequest, HpkePskRef, HpkePskSealRequest, HpkePskSenderSetupRequest,
    HpkeReceiverExportRequest, HpkeSealRequest, HpkeSenderExportRequest, HpkeSuite,
    HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
};
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};

const INFO: &[u8] = b"reallyme-hpke-operation-owner-v0.3";
const AAD: &[u8] = b"authenticated-operation-context";
const PLAINTEXT: &[u8] = b"secret operation payload";
const EXPORTER_CONTEXT: &[u8] = b"exporter-operation-context";
const PSK: &[u8] = &[0x5a; 32];
const PSK_ID: &[u8] = b"reviewed-high-entropy-psk";

#[test]
fn semantic_owner_executes_every_hpke_operation() {
    let suite = HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM;
    let generated = reallyme_crypto::hpke::keygen(suite).expect("key generation succeeds");
    assert_eq!(generated.public_key.len(), 65);
    assert_eq!(generated.private_key().len(), 32);

    let key_pair = reallyme_crypto::hpke::derive_keypair(suite, &[0x31; 32])
        .expect("deterministic key derivation succeeds");
    let arbitrary_ikm_key_pair = reallyme_crypto::hpke::derive_keypair_from_ikm(
        suite,
        b"arbitrary OpenMLS IKM with 256 bits",
    )
    .expect("arbitrary IKM derivation succeeds");
    assert_eq!(arbitrary_ikm_key_pair.public_key.len(), 65);
    let sealed = reallyme_crypto::hpke::seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &key_pair.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .expect("base seal succeeds");
    let opened = reallyme_crypto::hpke::open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: key_pair.private_key(),
        info: INFO,
        aad: AAD,
        ciphertext: &sealed.ciphertext,
    })
    .expect("base open succeeds");
    assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);

    let sender = reallyme_crypto::hpke::sender_export(&HpkeSenderExportRequest {
        suite,
        recipient_public_key: &key_pair.public_key,
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: 48,
    })
    .expect("sender export succeeds");
    let receiver = reallyme_crypto::hpke::receiver_export(&HpkeReceiverExportRequest {
        suite,
        encapsulated_key: &sender.encapsulated_key,
        recipient_private_key: key_pair.private_key(),
        info: INFO,
        exporter_context: EXPORTER_CONTEXT,
        output_length: 48,
    })
    .expect("receiver export succeeds");
    assert_eq!(sender.exporter_secret(), receiver.as_slice());

    let psk_sealed = reallyme_crypto::hpke::seal_psk(&HpkePskSealRequest {
        suite,
        recipient_public_key: &key_pair.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
        psk: PSK,
        psk_id: PSK_ID,
    })
    .expect("PSK seal succeeds");
    let psk_opened = reallyme_crypto::hpke::open_psk(&HpkePskOpenRequest {
        suite,
        encapsulated_key: &psk_sealed.encapsulated_key,
        recipient_private_key: key_pair.private_key(),
        info: INFO,
        aad: AAD,
        ciphertext: &psk_sealed.ciphertext,
        psk: PSK,
        psk_id: PSK_ID,
    })
    .expect("PSK open succeeds");
    assert_eq!(psk_opened.plaintext.as_slice(), PLAINTEXT);

    let mut split_sender = reallyme_crypto::hpke::setup_sender_psk(&HpkePskSenderSetupRequest {
        suite,
        recipient_public_key: &key_pair.public_key,
        info: INFO,
        psk: HpkePskRef::new(PSK).expect("PSK is valid"),
        psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
    })
    .expect("split PSK sender setup succeeds");
    let mut targeted_aad = AAD.to_vec();
    targeted_aad.extend_from_slice(&split_sender.encapsulated_key);
    let split_ciphertext = split_sender
        .context
        .seal(&targeted_aad, PLAINTEXT)
        .expect("split sender context seals");
    let mut split_receiver =
        reallyme_crypto::hpke::setup_receiver_psk(&HpkePskReceiverSetupRequest {
            suite,
            encapsulated_key: &split_sender.encapsulated_key,
            recipient_private_key: key_pair.private_key(),
            info: INFO,
            psk: HpkePskRef::new(PSK).expect("PSK is valid"),
            psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
        })
        .expect("split PSK receiver setup succeeds");
    let split_opened = split_receiver
        .open(&targeted_aad, &split_ciphertext)
        .expect("split PSK ciphertext opens");
    assert_eq!(split_opened.plaintext.as_slice(), PLAINTEXT);
}

#[test]
fn semantic_owner_preserves_specific_redacted_failure_reasons() {
    let suite = HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM;
    assert_eq!(
        reallyme_crypto::hpke::derive_keypair(suite, &[0_u8; 31]).map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidLength))
    );
    assert_eq!(
        reallyme_crypto::hpke::derive_keypair_from_ikm(suite, &[]).map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidLength))
    );
    assert_eq!(
        reallyme_crypto::hpke::derive_keypair_from_ikm(suite, &[0x5a; 31]).map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidLength))
    );

    let key_pair = reallyme_crypto::hpke::derive_keypair(suite, &[0x42; 32])
        .expect("deterministic key derivation succeeds");
    assert_eq!(
        reallyme_crypto::hpke::seal_base(&HpkeSealRequest {
            suite,
            recipient_public_key: &[0_u8; 1],
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
        })
        .map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidPublicKey))
    );

    let sealed = reallyme_crypto::hpke::seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &key_pair.public_key,
        info: INFO,
        aad: AAD,
        plaintext: PLAINTEXT,
    })
    .expect("base seal succeeds");
    assert_eq!(
        reallyme_crypto::hpke::open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: &[0_u8; 1],
            info: INFO,
            aad: AAD,
            ciphertext: &sealed.ciphertext,
        })
        .map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidPrivateKey))
    );
    assert_eq!(
        reallyme_crypto::hpke::open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &[0_u8; 1],
            recipient_private_key: key_pair.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &sealed.ciphertext,
        })
        .map(|_| ()),
        Err(primitive(PrimitiveErrorReason::MalformedCiphertext))
    );

    let mut tampered_ciphertext = sealed.ciphertext.clone();
    if let Some(first) = tampered_ciphertext.first_mut() {
        *first ^= 0x80;
    }
    assert_eq!(
        reallyme_crypto::hpke::open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key: &sealed.encapsulated_key,
            recipient_private_key: key_pair.private_key(),
            info: INFO,
            aad: AAD,
            ciphertext: &tampered_ciphertext,
        })
        .map(|_| ()),
        Err(primitive(PrimitiveErrorReason::VerificationFailed))
    );

    assert_eq!(
        reallyme_crypto::hpke::seal_psk(&HpkePskSealRequest {
            suite,
            recipient_public_key: &key_pair.public_key,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
            psk: &[],
            psk_id: PSK_ID,
        })
        .map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidParameter))
    );
    assert_eq!(
        reallyme_crypto::hpke::sender_export(&HpkeSenderExportRequest {
            suite,
            recipient_public_key: &key_pair.public_key,
            info: INFO,
            exporter_context: EXPORTER_CONTEXT,
            output_length: 0,
        })
        .map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidLength))
    );
}

#[test]
fn facade_exposes_explicit_raw_and_operation_error_boundaries() {
    let suite = HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM;

    assert_eq!(
        reallyme_crypto::hpke::derive_keypair_from_ikm_raw(suite, &[]).map(|_| ()),
        Err(HpkeError::InvalidInputKeyMaterial)
    );
    assert_eq!(
        reallyme_crypto::hpke::derive_keypair_from_ikm_operation(suite, &[]).map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidLength))
    );
    assert!(reallyme_crypto::hpke::derive_keypair_from_ikm_raw(suite, &[0x4d]).is_ok());
    assert_eq!(
        reallyme_crypto::hpke::derive_keypair_from_ikm_operation(suite, &[0x4d]).map(|_| ()),
        Err(primitive(PrimitiveErrorReason::InvalidLength))
    );

    let key_pair = reallyme_crypto::hpke::derive_keypair_raw(suite, &[0x61; 32])
        .expect("raw deterministic key derivation succeeds");
    let mut sender = reallyme_crypto::hpke::setup_sender_psk_raw(&HpkePskSenderSetupRequest {
        suite,
        recipient_public_key: &key_pair.public_key,
        info: INFO,
        psk: HpkePskRef::new(PSK).expect("PSK is valid"),
        psk_id: HpkePskIdRef::new(PSK_ID).expect("PSK identifier is valid"),
    })
    .expect("raw split sender setup succeeds");
    let mut targeted_aad = AAD.to_vec();
    targeted_aad.extend_from_slice(&sender.encapsulated_key);
    let ciphertext = sender
        .context
        .seal(&targeted_aad, PLAINTEXT)
        .expect("raw sender context preserves HPKE errors");
    let opened = reallyme_crypto::hpke::open_psk_raw(&HpkePskOpenRequest {
        suite,
        encapsulated_key: &sender.encapsulated_key,
        recipient_private_key: key_pair.private_key(),
        info: INFO,
        aad: &targeted_aad,
        ciphertext: &ciphertext,
        psk: PSK,
        psk_id: PSK_ID,
    })
    .expect("raw PSK open succeeds");
    assert_eq!(opened.plaintext.as_slice(), PLAINTEXT);
}

#[test]
fn registered_unavailable_components_fail_closed_without_fallback() {
    let unavailable_suite = HpkeSuite::new(
        HpkeKemId::DhKemCp256HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes256Gcm,
    );
    assert_eq!(
        reallyme_crypto::hpke::keygen(unavailable_suite).map(|_| ()),
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    );

    let invalid_combination = HpkeSuite::new(
        HpkeKemId::DhKemP256HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::ExportOnly,
    );
    let key_pair = reallyme_crypto::hpke::derive_keypair(invalid_combination, &[0x18; 32])
        .expect("export-only suite still supports KEM key derivation");
    assert_eq!(
        reallyme_crypto::hpke::seal_base(&HpkeSealRequest {
            suite: invalid_combination,
            recipient_public_key: &key_pair.public_key,
            info: INFO,
            aad: AAD,
            plaintext: PLAINTEXT,
        })
        .map(|_| ()),
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    );
}

fn primitive(reason: PrimitiveErrorReason) -> OperationError {
    OperationError::Primitive { reason }
}
