// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]
#![allow(missing_docs)]
#![cfg(all(feature = "native", feature = "hpke", feature = "test-vectors"))]

use reallyme_crypto::hpke::{
    derive_keypair, receiver_export_operation, seal_base_derand_operation, seal_base_derand_raw,
    sender_export_derand_operation, sender_export_derand_raw, HpkeDerandSealRequest,
    HpkeDerandSenderExportRequest, HpkeReceiverExportRequest,
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
};

#[test]
fn root_hpke_facade_exposes_deterministic_vector_mode_only_with_feature() {
    let suite = HPKE_MLKEM1024P384_SHAKE256_AES256GCM;
    let ikm = [0x37; 32];
    let recipient = derive_keypair(suite, &ikm).expect("recipient derivation must succeed");
    let randomness = vec![0x6d; suite.encapsulation_randomness_len().expect("supported KEM")];

    let first = seal_base_derand_raw(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: randomness.as_slice(),
        info: b"reallyme/root-vector-surface/v1",
        aad: b"context",
        plaintext: b"payload",
    })
    .expect("deterministic seal must succeed");
    let second = seal_base_derand_operation(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: randomness.as_slice(),
        info: b"reallyme/root-vector-surface/v1",
        aad: b"context",
        plaintext: b"payload",
    })
    .expect("deterministic seal must succeed");

    assert_eq!(first.encapsulated_key, second.encapsulated_key);
    assert_eq!(first.ciphertext, second.ciphertext);

    let export_request = HpkeDerandSenderExportRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: randomness.as_slice(),
        info: b"reallyme/root-vector-export/v1",
        exporter_context: b"openmls exporter context",
        output_length: 48,
    };
    let raw_export = sender_export_derand_raw(&export_request)
        .expect("raw deterministic sender export must succeed");
    let operation_export = sender_export_derand_operation(&export_request)
        .expect("operation deterministic sender export must succeed");
    assert_eq!(
        raw_export.encapsulated_key,
        operation_export.encapsulated_key
    );
    assert_eq!(
        raw_export.exporter_secret(),
        operation_export.exporter_secret()
    );

    let receiver_export = receiver_export_operation(&HpkeReceiverExportRequest {
        suite,
        encapsulated_key: &operation_export.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: b"reallyme/root-vector-export/v1",
        exporter_context: b"openmls exporter context",
        output_length: 48,
    })
    .expect("receiver export must match deterministic sender export");
    assert_eq!(
        operation_export.exporter_secret(),
        receiver_export.as_slice()
    );
}
