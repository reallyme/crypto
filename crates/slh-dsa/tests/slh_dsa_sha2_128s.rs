// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use crypto_core::CryptoError;
use crypto_slh_dsa::{
    decode_slh_dsa_sha2_128s_public_key, derive_slh_dsa_sha2_128s_keypair,
    encode_slh_dsa_sha2_128s_public_key, generate_slh_dsa_sha2_128s_keypair,
    sign_slh_dsa_sha2_128s, verify_slh_dsa_sha2_128s, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN,
    SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, SLH_DSA_SHA2_128S_SECRET_KEY_LEN,
    SLH_DSA_SHA2_128S_SIGNATURE_LEN,
};

const MESSAGE: &[u8] = b"reallyme slh-dsa sha2-128s conformance message";

fn deterministic_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let sk_seed = [0x11u8; SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN];
    let sk_prf = [0x22u8; SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN];
    let pk_seed = [0x33u8; SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN];
    let (public_key, secret_key) = derive_slh_dsa_sha2_128s_keypair(&sk_seed, &sk_prf, &pk_seed)?;
    Ok((public_key, secret_key.to_vec()))
}

#[test]
fn generated_keypair_has_expected_lengths() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_slh_dsa_sha2_128s_keypair()?;

    assert_eq!(public_key.len(), SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN);
    assert_eq!(secret_key.len(), SLH_DSA_SHA2_128S_SECRET_KEY_LEN);

    Ok(())
}

#[test]
fn deterministic_derivation_is_stable() -> Result<(), CryptoError> {
    let (public_a, secret_a) = deterministic_keypair()?;
    let (public_b, secret_b) = deterministic_keypair()?;

    assert_eq!(public_a, public_b);
    assert_eq!(secret_a, secret_b);

    Ok(())
}

#[test]
fn sign_and_verify_round_trip() -> Result<(), CryptoError> {
    let (public_key, secret_key) = deterministic_keypair()?;
    let signature = sign_slh_dsa_sha2_128s(&secret_key, MESSAGE)?;

    assert_eq!(signature.len(), SLH_DSA_SHA2_128S_SIGNATURE_LEN);
    verify_slh_dsa_sha2_128s(&public_key, MESSAGE, &signature)?;

    Ok(())
}

#[test]
fn verification_rejects_modified_message() -> Result<(), CryptoError> {
    let (public_key, secret_key) = deterministic_keypair()?;
    let signature = sign_slh_dsa_sha2_128s(&secret_key, MESSAGE)?;

    assert!(verify_slh_dsa_sha2_128s(&public_key, b"modified message", &signature).is_err());

    Ok(())
}

#[test]
fn verification_rejects_modified_signature() -> Result<(), CryptoError> {
    let (public_key, secret_key) = deterministic_keypair()?;
    let mut signature = sign_slh_dsa_sha2_128s(&secret_key, MESSAGE)?;
    signature[0] ^= 0x80;

    assert!(verify_slh_dsa_sha2_128s(&public_key, MESSAGE, &signature).is_err());

    Ok(())
}

#[test]
fn verification_rejects_wrong_public_key() -> Result<(), CryptoError> {
    let (_public_key, secret_key) = deterministic_keypair()?;
    let signature = sign_slh_dsa_sha2_128s(&secret_key, MESSAGE)?;
    let (wrong_public_key, _wrong_secret_key) = generate_slh_dsa_sha2_128s_keypair()?;

    assert!(verify_slh_dsa_sha2_128s(&wrong_public_key, MESSAGE, &signature).is_err());

    Ok(())
}

#[test]
fn public_key_encode_decode_validate_lengths() -> Result<(), CryptoError> {
    let (public_key, _secret_key) = deterministic_keypair()?;

    assert_eq!(
        encode_slh_dsa_sha2_128s_public_key(&public_key)?,
        public_key
    );
    assert_eq!(
        decode_slh_dsa_sha2_128s_public_key(&public_key)?,
        public_key
    );
    assert!(encode_slh_dsa_sha2_128s_public_key(&public_key[1..]).is_err());
    assert!(decode_slh_dsa_sha2_128s_public_key(&public_key[1..]).is_err());

    Ok(())
}

#[test]
fn malformed_inputs_are_rejected() -> Result<(), CryptoError> {
    let (public_key, secret_key) = deterministic_keypair()?;
    let signature = sign_slh_dsa_sha2_128s(&secret_key, MESSAGE)?;

    assert!(derive_slh_dsa_sha2_128s_keypair(&[], &[0u8; 16], &[0u8; 16]).is_err());
    assert!(sign_slh_dsa_sha2_128s(&secret_key[1..], MESSAGE).is_err());
    assert!(verify_slh_dsa_sha2_128s(&public_key[1..], MESSAGE, &signature).is_err());
    assert!(verify_slh_dsa_sha2_128s(&public_key, MESSAGE, &signature[1..]).is_err());

    Ok(())
}
