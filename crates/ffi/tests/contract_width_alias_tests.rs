// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(not(target_arch = "wasm32"))]

use crypto_core::contract_constants;

#[test]
fn ffi_width_aliases_preserve_the_reviewed_abi_dimensions() {
    assert_eq!(
        crypto_ffi::bip340_schnorr::SECP256K1_SECRET_KEY_LEN,
        contract_constants::secp256k1::SECP256K1_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::bip340_schnorr::SECP256K1_SECRET_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::bip340_schnorr::BIP340_SCHNORR_PUBLIC_KEY_LEN,
        contract_constants::secp256k1::BIP340_SCHNORR_PUBLIC_KEY_LEN
    );
    assert_eq!(
        crypto_ffi::bip340_schnorr::BIP340_SCHNORR_PUBLIC_KEY_LEN,
        32
    );
    assert_eq!(
        crypto_ffi::bip340_schnorr::BIP340_SCHNORR_MESSAGE_LEN,
        contract_constants::secp256k1::BIP340_SCHNORR_MESSAGE_LEN
    );
    assert_eq!(crypto_ffi::bip340_schnorr::BIP340_SCHNORR_MESSAGE_LEN, 32);
    assert_eq!(
        crypto_ffi::bip340_schnorr::BIP340_SCHNORR_AUX_RAND_LEN,
        contract_constants::secp256k1::BIP340_SCHNORR_AUX_RAND_LEN
    );
    assert_eq!(crypto_ffi::bip340_schnorr::BIP340_SCHNORR_AUX_RAND_LEN, 32);
    assert_eq!(
        crypto_ffi::bip340_schnorr::BIP340_SCHNORR_SIGNATURE_LEN,
        contract_constants::secp256k1::BIP340_SCHNORR_SIGNATURE_LEN
    );
    assert_eq!(crypto_ffi::bip340_schnorr::BIP340_SCHNORR_SIGNATURE_LEN, 64);
    assert_eq!(
        crypto_ffi::ed25519::ED25519_PUBLIC_KEY_LEN,
        contract_constants::ed25519::PUBLIC_KEY_LENGTH
    );
    assert_eq!(crypto_ffi::ed25519::ED25519_PUBLIC_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::ed25519::ED25519_SECRET_KEY_LEN,
        contract_constants::ed25519::ED25519_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::ed25519::ED25519_SECRET_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::ed25519::ED25519_SIGNATURE_LEN,
        contract_constants::ed25519::ED25519_SIGNATURE_LENGTH
    );
    assert_eq!(crypto_ffi::ed25519::ED25519_SIGNATURE_LEN, 64);
    assert_eq!(
        crypto_ffi::ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN,
        contract_constants::ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_44::ML_DSA_44_PUBLIC_KEY_LEN, 1312);
    assert_eq!(
        crypto_ffi::ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN,
        contract_constants::ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_44::ML_DSA_44_SECRET_SEED_LEN, 32);
    assert_eq!(
        crypto_ffi::ml_dsa_44::ML_DSA_44_SIGNATURE_LEN,
        contract_constants::ml_dsa_44::ML_DSA_44_SIGNATURE_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_44::ML_DSA_44_SIGNATURE_LEN, 2420);
    assert_eq!(
        crypto_ffi::ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN,
        contract_constants::ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_65::ML_DSA_65_PUBLIC_KEY_LEN, 1952);
    assert_eq!(
        crypto_ffi::ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN,
        contract_constants::ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_65::ML_DSA_65_SECRET_SEED_LEN, 32);
    assert_eq!(
        crypto_ffi::ml_dsa_65::ML_DSA_65_SIGNATURE_LEN,
        contract_constants::ml_dsa_65::ML_DSA_65_SIGNATURE_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_65::ML_DSA_65_SIGNATURE_LEN, 3309);
    assert_eq!(
        crypto_ffi::ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN,
        contract_constants::ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_87::ML_DSA_87_PUBLIC_KEY_LEN, 2592);
    assert_eq!(
        crypto_ffi::ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN,
        contract_constants::ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_87::ML_DSA_87_SECRET_SEED_LEN, 32);
    assert_eq!(
        crypto_ffi::ml_dsa_87::ML_DSA_87_SIGNATURE_LEN,
        contract_constants::ml_dsa_87::ML_DSA_87_SIGNATURE_LEN
    );
    assert_eq!(crypto_ffi::ml_dsa_87::ML_DSA_87_SIGNATURE_LEN, 4627);
    assert_eq!(
        crypto_ffi::ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN,
        contract_constants::ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_1024::ML_KEM_1024_PUBLIC_KEY_LEN, 1568);
    assert_eq!(
        crypto_ffi::ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN,
        contract_constants::ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_1024::ML_KEM_1024_SECRET_KEY_LEN, 64);
    assert_eq!(
        crypto_ffi::ml_kem_1024::ML_KEM_1024_CIPHERTEXT_LEN,
        contract_constants::ml_kem_1024::ML_KEM_1024_CIPHERTEXT_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_1024::ML_KEM_1024_CIPHERTEXT_LEN, 1568);
    assert_eq!(
        crypto_ffi::ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN,
        contract_constants::ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_1024::ML_KEM_1024_SHARED_SECRET_LEN, 32);
    assert_eq!(
        crypto_ffi::ml_kem_1024::ML_KEM_1024_ENCAPS_RANDOMNESS_LEN,
        contract_constants::ml_kem_1024::ML_KEM_1024_ENCAPS_RANDOMNESS_LEN
    );
    assert_eq!(
        crypto_ffi::ml_kem_1024::ML_KEM_1024_ENCAPS_RANDOMNESS_LEN,
        32
    );
    assert_eq!(
        crypto_ffi::ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN,
        contract_constants::ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_512::ML_KEM_512_PUBLIC_KEY_LEN, 800);
    assert_eq!(
        crypto_ffi::ml_kem_512::ML_KEM_512_SECRET_KEY_LEN,
        contract_constants::ml_kem_512::ML_KEM_512_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_512::ML_KEM_512_SECRET_KEY_LEN, 64);
    assert_eq!(
        crypto_ffi::ml_kem_512::ML_KEM_512_CIPHERTEXT_LEN,
        contract_constants::ml_kem_512::ML_KEM_512_CIPHERTEXT_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_512::ML_KEM_512_CIPHERTEXT_LEN, 768);
    assert_eq!(
        crypto_ffi::ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN,
        contract_constants::ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_512::ML_KEM_512_SHARED_SECRET_LEN, 32);
    assert_eq!(
        crypto_ffi::ml_kem_512::ML_KEM_512_ENCAPS_RANDOMNESS_LEN,
        contract_constants::ml_kem_512::ML_KEM_512_ENCAPS_RANDOMNESS_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_512::ML_KEM_512_ENCAPS_RANDOMNESS_LEN, 32);
    assert_eq!(
        crypto_ffi::ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN,
        contract_constants::ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN, 1184);
    assert_eq!(
        crypto_ffi::ml_kem_768::ML_KEM_768_SECRET_KEY_LEN,
        contract_constants::ml_kem_768::ML_KEM_768_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_768::ML_KEM_768_SECRET_KEY_LEN, 64);
    assert_eq!(
        crypto_ffi::ml_kem_768::ML_KEM_768_CIPHERTEXT_LEN,
        contract_constants::ml_kem_768::ML_KEM_768_CIPHERTEXT_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_768::ML_KEM_768_CIPHERTEXT_LEN, 1088);
    assert_eq!(
        crypto_ffi::ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN,
        contract_constants::ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_768::ML_KEM_768_SHARED_SECRET_LEN, 32);
    assert_eq!(
        crypto_ffi::ml_kem_768::ML_KEM_768_ENCAPS_RANDOMNESS_LEN,
        contract_constants::ml_kem_768::ML_KEM_768_ENCAPS_RANDOMNESS_LEN
    );
    assert_eq!(crypto_ffi::ml_kem_768::ML_KEM_768_ENCAPS_RANDOMNESS_LEN, 32);
    assert_eq!(
        crypto_ffi::p256::P256_SECRET_KEY_LEN,
        contract_constants::p256::P256_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::p256::P256_SECRET_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::p256::P256_PUBLIC_KEY_COMPRESSED_LEN,
        contract_constants::p256::P256_PUBLIC_KEY_COMPRESSED_LEN
    );
    assert_eq!(crypto_ffi::p256::P256_PUBLIC_KEY_COMPRESSED_LEN, 33);
    assert_eq!(
        crypto_ffi::p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN,
        contract_constants::p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN
    );
    assert_eq!(crypto_ffi::p256::P256_PUBLIC_KEY_UNCOMPRESSED_LEN, 65);
    assert_eq!(
        crypto_ffi::p256::P256_SHARED_SECRET_LEN,
        contract_constants::p256::P256_SHARED_SECRET_LEN
    );
    assert_eq!(crypto_ffi::p256::P256_SHARED_SECRET_LEN, 32);
    assert_eq!(
        crypto_ffi::secp256k1::SECP256K1_SECRET_KEY_LEN,
        contract_constants::secp256k1::SECP256K1_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::secp256k1::SECP256K1_SECRET_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
        contract_constants::secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN
    );
    assert_eq!(
        crypto_ffi::secp256k1::SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
        33
    );
    assert_eq!(
        crypto_ffi::secp256k1::SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN,
        contract_constants::secp256k1::SECP256K1_UNCOMPRESSED_PUBLIC_KEY_LEN
    );
    assert_eq!(
        crypto_ffi::secp256k1::SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN,
        65
    );
    assert_eq!(
        crypto_ffi::secp256k1::SECP256K1_SIGNATURE_LEN,
        contract_constants::secp256k1::SECP256K1_ECDSA_JOSE_SIGNATURE_LEN
    );
    assert_eq!(crypto_ffi::secp256k1::SECP256K1_SIGNATURE_LEN, 64);
    assert_eq!(
        crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN,
        contract_constants::slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN,
        contract_constants::slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN
    );
    assert_eq!(crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_SECRET_KEY_LEN, 64);
    assert_eq!(
        crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_SIGNATURE_LEN,
        contract_constants::slh_dsa::SLH_DSA_SHA2_128S_SIGNATURE_LEN
    );
    assert_eq!(crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_SIGNATURE_LEN, 7856);
    assert_eq!(
        crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN,
        contract_constants::slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
    );
    assert_eq!(crypto_ffi::slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN, 16);
    assert_eq!(
        crypto_ffi::x25519::X25519_PUBLIC_KEY_LEN,
        contract_constants::x25519::X25519_PUBLIC_KEY_LEN
    );
    assert_eq!(crypto_ffi::x25519::X25519_PUBLIC_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::x25519::X25519_SECRET_KEY_LEN,
        contract_constants::x25519::X25519_PRIVATE_KEY_LEN
    );
    assert_eq!(crypto_ffi::x25519::X25519_SECRET_KEY_LEN, 32);
    assert_eq!(
        crypto_ffi::x25519::X25519_SHARED_SECRET_LEN,
        contract_constants::x25519::X25519_SHARED_SECRET_LEN
    );
    assert_eq!(crypto_ffi::x25519::X25519_SHARED_SECRET_LEN, 32);
}
