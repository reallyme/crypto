// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz fixed-width post-quantum public-key, ciphertext, and signature
//! boundaries. The harness expands arbitrary mutations to the required wire
//! widths so parsers are exercised beyond their outer length checks.

#![no_main]

use crypto_ml_dsa_44::{
    decode_public_key as decode_ml_dsa_44_public_key, verify_ml_dsa_44, ML_DSA_44_PUBLIC_KEY_LEN,
    ML_DSA_44_SIGNATURE_LEN,
};
use crypto_ml_dsa_65::{
    decode_public_key as decode_ml_dsa_65_public_key, verify_ml_dsa_65, ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SIGNATURE_LEN,
};
use crypto_ml_dsa_87::{
    decode_public_key as decode_ml_dsa_87_public_key, verify_ml_dsa_87, ML_DSA_87_PUBLIC_KEY_LEN,
    ML_DSA_87_SIGNATURE_LEN,
};
use crypto_ml_kem_1024::{
    decode_public_key as decode_ml_kem_1024_public_key, ml_kem_1024_decapsulate,
    ML_KEM_1024_PUBLIC_KEY_LEN, ML_KEM_1024_SECRET_KEY_LEN,
};
use crypto_ml_kem_512::{
    decode_public_key as decode_ml_kem_512_public_key, ml_kem_512_decapsulate,
    ML_KEM_512_PUBLIC_KEY_LEN, ML_KEM_512_SECRET_KEY_LEN,
};
use crypto_ml_kem_768::{
    decode_public_key as decode_ml_kem_768_public_key, ml_kem_768_decapsulate,
    ML_KEM_768_PUBLIC_KEY_LEN, ML_KEM_768_SECRET_KEY_LEN,
};
use crypto_slh_dsa::{
    decode_slh_dsa_sha2_128s_public_key, verify_slh_dsa_sha2_128s,
    SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, SLH_DSA_SHA2_128S_SIGNATURE_LEN,
};
use libfuzzer_sys::fuzz_target;

const ML_KEM_512_CIPHERTEXT_LEN: usize = 768;
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;

fn expanded_candidate(input: &[u8], length: usize, domain: u8) -> Vec<u8> {
    let mut candidate = vec![domain; length];
    for (destination, source) in candidate.iter_mut().zip(input) {
        *destination ^= *source;
    }
    candidate
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };

    match selector % 7 {
        0 => {
            let public_key =
                expanded_candidate(input, ML_KEM_512_PUBLIC_KEY_LEN, selector.rotate_left(1));
            let ciphertext =
                expanded_candidate(input, ML_KEM_512_CIPHERTEXT_LEN, selector.rotate_right(1));
            let secret_key = [selector; ML_KEM_512_SECRET_KEY_LEN];
            let _ = decode_ml_kem_512_public_key(&public_key);
            let _ = ml_kem_512_decapsulate(&ciphertext, &secret_key);
        }
        1 => {
            let public_key =
                expanded_candidate(input, ML_KEM_768_PUBLIC_KEY_LEN, selector.rotate_left(1));
            let ciphertext =
                expanded_candidate(input, ML_KEM_768_CIPHERTEXT_LEN, selector.rotate_right(1));
            let secret_key = [selector; ML_KEM_768_SECRET_KEY_LEN];
            let _ = decode_ml_kem_768_public_key(&public_key);
            let _ = ml_kem_768_decapsulate(&ciphertext, &secret_key);
        }
        2 => {
            let public_key =
                expanded_candidate(input, ML_KEM_1024_PUBLIC_KEY_LEN, selector.rotate_left(1));
            let ciphertext =
                expanded_candidate(input, ML_KEM_1024_CIPHERTEXT_LEN, selector.rotate_right(1));
            let secret_key = [selector; ML_KEM_1024_SECRET_KEY_LEN];
            let _ = decode_ml_kem_1024_public_key(&public_key);
            let _ = ml_kem_1024_decapsulate(&ciphertext, &secret_key);
        }
        3 => {
            let public_key = expanded_candidate(input, ML_DSA_44_PUBLIC_KEY_LEN, selector);
            let signature =
                expanded_candidate(input, ML_DSA_44_SIGNATURE_LEN, selector.rotate_left(1));
            let _ = decode_ml_dsa_44_public_key(&public_key);
            let _ = verify_ml_dsa_44(&public_key, b"reallyme-fuzz", &signature);
        }
        4 => {
            let public_key = expanded_candidate(input, ML_DSA_65_PUBLIC_KEY_LEN, selector);
            let signature =
                expanded_candidate(input, ML_DSA_65_SIGNATURE_LEN, selector.rotate_left(1));
            let _ = decode_ml_dsa_65_public_key(&public_key);
            let _ = verify_ml_dsa_65(&public_key, b"reallyme-fuzz", &signature);
        }
        5 => {
            let public_key = expanded_candidate(input, ML_DSA_87_PUBLIC_KEY_LEN, selector);
            let signature =
                expanded_candidate(input, ML_DSA_87_SIGNATURE_LEN, selector.rotate_left(1));
            let _ = decode_ml_dsa_87_public_key(&public_key);
            let _ = verify_ml_dsa_87(&public_key, b"reallyme-fuzz", &signature);
        }
        _ => {
            let public_key = expanded_candidate(input, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, selector);
            let signature = expanded_candidate(
                input,
                SLH_DSA_SHA2_128S_SIGNATURE_LEN,
                selector.rotate_left(1),
            );
            let _ = decode_slh_dsa_sha2_128s_public_key(&public_key);
            let _ = verify_slh_dsa_sha2_128s(&public_key, b"reallyme-fuzz", &signature);
        }
    }
});
