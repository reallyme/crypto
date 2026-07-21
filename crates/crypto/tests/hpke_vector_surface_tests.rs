// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]
#![allow(missing_docs)]
#![cfg(all(feature = "native", feature = "hpke", feature = "test-vectors"))]

use reallyme_crypto::hpke::{
    derive_keypair, seal_base_derand, HpkeDerandSealRequest, HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
};

#[test]
fn root_hpke_facade_exposes_deterministic_vector_mode_only_with_feature() {
    let suite = HPKE_MLKEM1024P384_SHAKE256_AES256GCM;
    let ikm = [0x37; 32];
    let recipient = derive_keypair(suite, &ikm).expect("recipient derivation must succeed");
    let randomness = vec![0x6d; suite.encapsulation_randomness_len().expect("supported KEM")];

    let first = seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        encapsulation_randomness: randomness.as_slice(),
        info: b"reallyme/root-vector-surface/v1",
        aad: b"context",
        plaintext: b"payload",
    })
    .expect("deterministic seal must succeed");
    let second = seal_base_derand(&HpkeDerandSealRequest {
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
}
