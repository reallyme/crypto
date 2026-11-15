// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Compiled only as an integration test in the pinned IETF reference package.
use std::{env, fs};

use hpke_ref::{
    Aead, Aes128Gcm, Aes256Gcm, ChaChaPoly, Context, HkdfSha256, HkdfSha384, Instance, Kdf, Kem,
    MlKem512, MlKem768, MlKem768X25519, MlKem1024, Mode, Sender, Shake256,
    test_vectors::{EncryptionVector, ExportVector, TestVector},
};
use sha3::digest::{ExtendableOutput, Update, XofReader};

// Public fixture bytes from the RFC 9180 PSK vectors.
const PSK: [u8; 32] =
    hex_literal::hex!("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
const PSK_ID: &[u8] = b"Ennyn Durin aran Moria";

#[test]
fn generate_psk_context_pairs() {
    let input = env::var_os("HPKE_PSK_VECTOR_INPUT").expect("Base vector path");
    let output = env::var_os("HPKE_PSK_VECTOR_OUTPUT").expect("PSK vector path");
    let base: Vec<TestVector> =
        serde_json::from_slice(&fs::read(input).expect("read Base corpus")).expect("Base corpus");
    let mut paired = Vec::new();
    append_pair::<MlKem512, HkdfSha256, Aes128Gcm>(&base, &mut paired);
    append_pair::<MlKem768, HkdfSha256, Aes128Gcm>(&base, &mut paired);
    append_pair::<MlKem1024, HkdfSha384, Aes256Gcm>(&base, &mut paired);
    append_pair::<MlKem768X25519, HkdfSha256, ChaChaPoly>(&base, &mut paired);
    append_pair::<MlKem768X25519, Shake256, ChaChaPoly>(&base, &mut paired);

    let mut encoded = serde_json::to_vec_pretty(&paired).expect("encode PSK corpus");
    encoded.push(b'\n');
    fs::write(output, encoded).expect("write PSK corpus");
}

fn append_pair<K: Kem, H: Kdf, A: Aead>(base: &[TestVector], output: &mut Vec<TestVector>) {
    let suite_id = Instance::<K, H, A>::suite_id();
    let anchor = base
        .iter()
        .find(|vector| vector.mode == u8::from(Mode::Base) && vector.suite_id == suite_id)
        .expect("published Base vector for the suite");
    anchor
        .verify()
        .expect("reference opens the published Base records");
    assert_eq!(anchor.ikm_e.len(), K::N_RANDOM);

    // Keep the recipient and all record inputs fixed while deriving a
    // reproducible second encapsulation input for this public fixture.
    let mut shake = sha3::Shake256::default();
    shake.update(b"HPKE PSK vector second encapsulation");
    shake.update(&suite_id);
    shake.update(&anchor.ikm_e);
    let mut alternate_input = vec![0; K::N_RANDOM];
    shake.finalize_xof().read(&mut alternate_input);

    let first = psk_vector::<K, H, A>(anchor, anchor.ikm_e.clone());
    let second = psk_vector::<K, H, A>(anchor, alternate_input);
    assert!(first.enc == anchor.enc && first.shared_secret == anchor.shared_secret);
    assert!(first.enc != second.enc && first.shared_secret != second.shared_secret);
    first
        .verify()
        .expect("reference opens the first PSK records");
    second
        .verify()
        .expect("reference opens the second PSK records");
    output.extend([first, second]);
}

fn psk_vector<K: Kem, H: Kdf, A: Aead>(anchor: &TestVector, ikm_e: Vec<u8>) -> TestVector {
    let suite_id = Instance::<K, H, A>::suite_id();
    let (private_key, public_key) = K::derive_key_pair(&anchor.ikm_r);
    let (shared_secret, enc) = K::encap_derand(&public_key, &ikm_e);
    let (key, base_nonce, exporter_secret) = H::combine_secrets(
        &suite_id,
        Mode::Psk,
        &shared_secret,
        &anchor.info,
        &PSK,
        PSK_ID,
        A::N_K,
        A::N_N,
    );
    let mut sender =
        Context::<A, Sender>::new(key.clone(), base_nonce.clone(), exporter_secret.clone());
    let encryptions = anchor
        .encryptions
        .iter()
        .map(|record| EncryptionVector::generate(&mut sender, &record.pt, &record.aad))
        .collect();
    let exports = anchor
        .exports
        .iter()
        .map(|export| {
            ExportVector::generate::<H>(
                &suite_id,
                &exporter_secret,
                &export.exporter_context,
                export.length,
            )
        })
        .collect();

    TestVector {
        mode: Mode::Psk.into(),
        kem_id: anchor.kem_id,
        kdf_id: anchor.kdf_id,
        aead_id: anchor.aead_id,
        info: anchor.info.clone(),
        ikm_e,
        ikm_r: anchor.ikm_r.clone(),
        sk_rm: K::serialize_private_key(&private_key),
        pk_rm: K::serialize_public_key(&public_key),
        enc,
        shared_secret,
        suite_id: suite_id.to_vec(),
        key,
        base_nonce,
        exporter_secret,
        psk: Some(PSK.to_vec()),
        psk_id: Some(PSK_ID.to_vec()),
        encryptions,
        exports,
    }
}
