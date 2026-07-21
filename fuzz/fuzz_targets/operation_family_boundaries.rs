// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz operation-family boundary parsers that are easy to bypass with only
//! raw protobuf fuzzing: HPKE component identifiers and sealed-message inputs,
//! KDF wrappers, and PBKDF2 iteration/profile validation.

#![no_main]

use crypto_concat_kdf::{
    derive_jwa_concat_kdf_sha256, JwaAlgorithmId, JwaConcatKdfRequest, JwaPartyInfo,
    JwaSharedSecret,
};
use crypto_hkdf::{derive, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite};
use crypto_hpke::{
    open_base, open_psk, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkePskOpenRequest,
    HpkeSuite, HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM, HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM, HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM, HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM, HPKE_MLKEM1024_SHAKE256_AES256GCM,
    HPKE_MLKEM512_HKDF_SHA256_AES128GCM, HPKE_MLKEM768P256_SHAKE256_AES256GCM,
    HPKE_MLKEM768_SHAKE256_AES256GCM, HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
};
use crypto_pbkdf2::{Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Salt};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_SLICE_LEN: usize = 4096;
const REVIEWED_HPKE_SUITES: [HpkeSuite; 12] = [
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM,
    HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
    HPKE_MLKEM512_HKDF_SHA256_AES128GCM,
    HPKE_MLKEM768_SHAKE256_AES256GCM,
    HPKE_MLKEM1024_SHAKE256_AES256GCM,
    HPKE_MLKEM768P256_SHAKE256_AES256GCM,
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
    HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
];

fn bounded(input: &[u8]) -> &[u8] {
    let end = input.len().min(MAX_FUZZ_SLICE_LEN);
    &input[..end]
}

fn read_u16(input: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = input.get(offset..end)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = input.get(offset..end)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn split3(input: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let first_end = input.len() / 3;
    let second_end = match first_end.checked_mul(2) {
        Some(end) => end,
        None => input.len(),
    };
    (
        &input[..first_end],
        &input[first_end..second_end],
        &input[second_end..],
    )
}

fn exercise_kdf_boundaries(data: &[u8]) {
    let (left, middle, right) = split3(bounded(data));

    let ikm = HkdfInputKeyMaterial::from_slice(left);
    let salt = HkdfSalt::from_slice(middle);
    let info = HkdfInfo::from_slice(right);
    for suite in [
        HkdfSuite::Sha2_256,
        HkdfSuite::Sha2_384,
        HkdfSuite::Sha3_256,
    ] {
        let _ = derive::<32>(&DeriveRequest {
            suite,
            ikm: &ikm,
            salt: Some(&salt),
            info: &info,
        });
    }

    let prf = if data.first().copied().unwrap_or_default() & 1 == 0 {
        Pbkdf2Prf::HmacSha256
    } else {
        Pbkdf2Prf::HmacSha512
    };
    let _ = Pbkdf2Password::from_slice(left, prf);
    let _ = Pbkdf2Salt::from_slice(middle, prf);
    if let Some(iterations) = read_u32(data, 0) {
        let _ = Pbkdf2Iterations::from_u32(iterations, prf);
        let _ = Pbkdf2Iterations::from_u32_modern(iterations, prf);
    }

    let shared_secret = JwaSharedSecret::from_slice(left);
    let algorithm_id = JwaAlgorithmId::from_slice(middle);
    let party_u_info = JwaPartyInfo::from_slice(right);
    let party_v_info = JwaPartyInfo::from_slice(&[]);
    if let (Ok(shared_secret), Ok(algorithm_id), Ok(party_u_info), Ok(party_v_info)) =
        (shared_secret, algorithm_id, party_u_info, party_v_info)
    {
        let _ = derive_jwa_concat_kdf_sha256::<32>(&JwaConcatKdfRequest {
            shared_secret: &shared_secret,
            algorithm_id: &algorithm_id,
            party_u_info: &party_u_info,
            party_v_info: &party_v_info,
        });
    }
}

fn exercise_hpke_suite(suite: HpkeSuite, payload: &[u8]) {
    let Ok(encapsulated_key_len) = suite.encapsulated_key_len() else {
        return;
    };
    let Ok(private_key_len) = suite.private_key_len() else {
        return;
    };
    let Some(key_material_len) = encapsulated_key_len.checked_add(private_key_len) else {
        return;
    };
    // Bound only the attacker-controlled ciphertext tail. Bounding the entire
    // payload would make suites with large post-quantum private keys
    // unreachable and turn their fuzz coverage into a false green.
    let Some(max_payload_len) = key_material_len.checked_add(MAX_FUZZ_SLICE_LEN) else {
        return;
    };
    let payload_end = payload.len().min(max_payload_len);
    let payload = &payload[..payload_end];
    if payload.len() < key_material_len {
        return;
    }
    let (encapsulated_key, remainder) = payload.split_at(encapsulated_key_len);
    let (private_key, ciphertext) = remainder.split_at(private_key_len);
    let _ = suite.tag_len();
    let _ = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key,
        recipient_private_key: private_key,
        info: b"reallyme-fuzz-hpke",
        aad: b"reallyme-fuzz-aad",
        ciphertext,
    });
    let _ = open_psk(&HpkePskOpenRequest {
        suite,
        encapsulated_key,
        recipient_private_key: private_key,
        info: b"reallyme-fuzz-hpke",
        aad: b"reallyme-fuzz-aad",
        ciphertext,
        psk: private_key,
        psk_id: b"reallyme-fuzz-psk",
    });
}

fn exercise_hpke_boundaries(data: &[u8]) {
    if let (Some(kem_id), Some(kdf_id), Some(aead_id), Some(payload)) = (
        read_u16(data, 0),
        read_u16(data, 2),
        read_u16(data, 4),
        data.get(6..),
    ) {
        let kem = HpkeKemId::try_from(kem_id);
        let kdf = HpkeKdfId::try_from(kdf_id);
        let aead = HpkeAeadId::try_from(aead_id);
        if let (Ok(kem), Ok(kdf), Ok(aead)) = (kem, kdf, aead) {
            exercise_hpke_suite(HpkeSuite::new(kem, kdf, aead), payload);
        }
    }

    if let Some((selector, payload)) = data.split_first() {
        let index = usize::from(*selector) % REVIEWED_HPKE_SUITES.len();
        exercise_hpke_suite(REVIEWED_HPKE_SUITES[index], payload);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_kdf_boundaries(data);
    exercise_hpke_boundaries(data);
});
