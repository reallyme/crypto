// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Deterministic generator that writes the cross-implementation conformance
//! vectors (keys, signatures, AEAD, KEM, hashing, and codec fixtures) consumed
//! by the workspace's vector tests.

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use codec_base64url::bytes_to_base64url;
use codec_cbor::{compute_cid_dag_cbor, encode_dag_cbor, CborValue};
use codec_multibase::{bytes_to_multibase58btc, bytes_to_multibase_base64url};
use codec_multicodec::{lookup_codec_prefix, MULTICODEC_TABLE};
use codec_multikey::encode_multikey;
use crypto_aes256_gcm::{
    decrypt, encrypt, Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest,
    EncryptRequest,
};
use crypto_aes256_gcm_siv::{
    decrypt as gcm_siv_decrypt, encrypt as gcm_siv_encrypt, Aes256GcmSivKey, Aes256GcmSivNonce,
    CiphertextWithTag as GcmSivCiphertextWithTag, DecryptRequest as GcmSivDecryptRequest,
    EncryptRequest as GcmSivEncryptRequest,
};
use crypto_aes_kw::{unwrap_key as aes_kw_unwrap_key, wrap_key as aes_kw_wrap_key, Aes256KwKek};
use crypto_argon2id::{
    derive_key as argon2id_derive_key, Argon2Profile, Argon2Salt, Argon2Secret, DeriveKeyRequest,
};
use crypto_chacha20_poly1305::{
    decrypt as chacha_decrypt, decrypt_xchacha20_poly1305, encrypt as chacha_encrypt,
    encrypt_xchacha20_poly1305, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce,
    CiphertextWithTag as ChaChaCiphertextWithTag, DecryptRequest as ChaChaDecryptRequest,
    EncryptRequest as ChaChaEncryptRequest, XChaCha20Poly1305DecryptRequest,
    XChaCha20Poly1305EncryptRequest, XChaCha20Poly1305Nonce,
};
use crypto_core::MacAlgorithm;
use crypto_ed25519::{sign_ed25519, verify_ed25519};
use crypto_hkdf::{
    derive as hkdf_derive, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite,
};
use crypto_hmac::{authenticate as hmac_authenticate, HmacKey};
use crypto_hpke::{
    open_base as hpke_open_base, seal_base_derand as hpke_seal_base_derand, HpkeDerandSealRequest,
    HpkeOpenRequest, HpkeSuite,
};
use crypto_p256::{
    decompress_p256, derive_p256_shared_secret, sign_p256_der_prehash, verify_p256_der_prehash,
};
use crypto_p384::{decompress_p384, sign_p384_der_prehash};
use crypto_p521::{decompress_p521, sign_p521_der_prehash};
use crypto_pbkdf2::{
    derive_key as derive_pbkdf2_key, Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request,
    Pbkdf2Salt,
};
use crypto_rsa::{
    verify_rsa_pkcs1v15, verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding,
};
use crypto_secp256k1::{
    derive_bip340_schnorr_public_key, sign_bip340_schnorr, sign_secp256k1, verify_bip340_schnorr,
    verify_secp256k1,
};
use crypto_sha2::{digest_sha2_384, digest_sha2_512};
use crypto_sha2_256::digest as sha2_256_digest;
use crypto_sha3::{digest_sha3_224, digest_sha3_384, digest_sha3_512};
use crypto_sha3_256::digest as sha3_256_digest;
use crypto_slh_dsa::{
    derive_slh_dsa_sha2_128s_keypair, sign_slh_dsa_sha2_128s, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN,
};
use crypto_x25519::derive_x25519_shared_secret;
use crypto_x_wing::{
    generate_x_wing_1024_keypair_derand, generate_x_wing_768_keypair_derand,
    x_wing_1024_encapsulate_derand, x_wing_768_encapsulate_derand,
};
use ed25519_dalek_conformance::SigningKey as Ed25519SigningKey;
use envelopes_jwk::{
    ed25519_public_key_to_jwk, ed25519_public_key_to_jwk_jcs, mldsa44_public_key_to_jwk,
    mldsa44_public_key_to_jwk_jcs, mldsa65_public_key_to_jwk, mldsa65_public_key_to_jwk_jcs,
    mldsa87_public_key_to_jwk, mldsa87_public_key_to_jwk_jcs, mlkem1024_public_key_to_jwk,
    mlkem1024_public_key_to_jwk_jcs, mlkem512_public_key_to_jwk, mlkem512_public_key_to_jwk_jcs,
    mlkem768_public_key_to_jwk, mlkem768_public_key_to_jwk_jcs, p256_public_key_to_jwk,
    p256_public_key_to_jwk_jcs, secp256k1_public_key_to_jwk, secp256k1_public_key_to_jwk_jcs,
    slh_dsa_sha2_128s_public_key_to_jwk_jcs, x25519_public_key_to_jwk,
    x25519_public_key_to_jwk_jcs, x_wing_1024_public_key_to_jwk_jcs,
    x_wing_768_public_key_to_jwk_jcs, Jwk, JwkOptions,
};
use envelopes_jwk_multikey::jwk_to_multikey;
use k256_conformance::ecdsa::SigningKey as Secp256k1SigningKey;
use ml_dsa_conformance::{
    KeyExport as MlDsaKeyExport, Keypair as MlDsaKeypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
    Seed as MlDsaSeed, SignatureEncoding, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey,
};
use ml_kem_conformance::{
    kem::Decapsulate as MlKemDecapsulate,
    ml_kem_1024::{
        Ciphertext as MlKem1024Ciphertext, DecapsulationKey as MlKem1024DecapsulationKey,
    },
    ml_kem_512::{Ciphertext as MlKem512Ciphertext, DecapsulationKey as MlKem512DecapsulationKey},
    ml_kem_768::{Ciphertext as MlKem768Ciphertext, DecapsulationKey as MlKem768DecapsulationKey},
    Seed as MlKemSeed, B32 as MlKemB32,
};
use p256_conformance::{ecdsa::SigningKey as P256SigningKey, SecretKey as P256SecretKey};
use p384_conformance::{ecdsa::SigningKey as P384SigningKey, SecretKey as P384SecretKey};
use p521_conformance::{ecdsa::SigningKey as P521SigningKey, SecretKey as P521SecretKey};
use serde::Serialize;
use thiserror::Error;
use x25519_dalek_conformance::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const AES_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const AES_NONCE: [u8; 12] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
];
const AES_AAD: &[u8] = b"reallyme-crypto-vector-aad";
const AES_PLAINTEXT: &[u8] = b"ReallyMe AES-256-GCM conformance vector";
const AES_KW_KEY_DATA: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const CHACHA_KEY: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const CHACHA_NONCE: [u8; 12] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
];
const XCHACHA_NONCE: [u8; 24] = [
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];
const CHACHA_AAD: &[u8] = b"reallyme-crypto-chacha-vector-aad";
const CHACHA_PLAINTEXT: &[u8] = b"ReallyMe ChaCha20-Poly1305 conformance vector";
const GCM_SIV_KEY: [u8; 32] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
const GCM_SIV_NONCE: [u8; 12] = [
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
];
const GCM_SIV_AAD: &[u8] = b"reallyme-crypto-gcm-siv-vector-aad";
const GCM_SIV_PLAINTEXT: &[u8] = b"ReallyMe AES-256-GCM-SIV conformance vector";
// Argon2id V1 profile: Argon2id, v0x13, m=262144 KiB, t=3, p=1, 32-byte output.
const ARGON2ID_SECRET: &[u8] = b"ReallyMe Argon2id conformance secret";
const ARGON2ID_SALT: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];
const HMAC_KEY: [u8; 20] = [0x0b; 20];
const HMAC_MESSAGE: &[u8] = b"Hi There";
const PBKDF2_PASSWORD: &[u8] = b"password";
const PBKDF2_SALT: &[u8] = b"salt";
const PBKDF2_ITERATIONS: u32 = 4096;
const SIGNATURE_MESSAGE: &[u8] = b"ReallyMe signature conformance vector";
const HASH_MESSAGE: &[u8] = b"ReallyMe SHA conformance vector";
const CODEC_BYTES: &[u8] = b"ReallyMe codec vector";
const HPKE_INFO: &[u8] = b"reallyme-hpke-rfc9180-info";
const HPKE_AAD: &[u8] = b"reallyme-hpke-rfc9180-aad";
const HPKE_PLAINTEXT: &[u8] = b"ReallyMe HPKE RFC 9180 Base vector";
const HPKE_P256_ENCAPS_SEED: [u8; 32] = [
    0xa8, 0x31, 0x0f, 0x95, 0xc4, 0x62, 0x72, 0x1d, 0x58, 0x9e, 0x20, 0xbb, 0x06, 0x31, 0x6f, 0xe4,
    0x5c, 0xd7, 0x81, 0x2a, 0x93, 0x4f, 0xb5, 0x60, 0x1a, 0xea, 0x3d, 0x0c, 0x77, 0x84, 0x19, 0x2e,
];
const HPKE_X25519_ENCAPS_SEED: [u8; 32] = [
    0xc2, 0x54, 0x8a, 0x39, 0xef, 0x12, 0x67, 0x90, 0x41, 0xb3, 0xdc, 0x6a, 0x18, 0xf5, 0x23, 0x7e,
    0x9b, 0x04, 0xd1, 0x68, 0x35, 0xca, 0x82, 0x0f, 0x57, 0xbe, 0x29, 0x91, 0xe4, 0x40, 0x7c, 0x15,
];
/// Message signed by the ML-DSA KATs. Committed to the vectors so every
/// runtime lane signs and verifies the exact same bytes.
const ML_DSA_MESSAGE: &[u8] = b"ReallyMe ML-DSA conformance message";
const SLH_DSA_MESSAGE: &[u8] = b"ReallyMe SLH-DSA conformance message";
/// Fixed 32-byte encapsulation randomness (`m` in FIPS 203) so ML-KEM
/// encapsulation is deterministic and every implementation must reproduce
/// the same ciphertext and shared secret.
const ML_KEM_ENCAPS_RANDOMNESS: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
];
const X_WING_SECRET_SEED: [u8; 32] = [
    0x58, 0x12, 0xa3, 0x0d, 0x9b, 0x71, 0x44, 0x06, 0xc2, 0x83, 0x5f, 0xbe, 0x9d, 0x40, 0x2a, 0x77,
    0x31, 0xca, 0x8e, 0x19, 0xd6, 0x52, 0x90, 0xa4, 0x0f, 0xb5, 0xc8, 0x66, 0xe1, 0x23, 0x7a, 0x5d,
];
const X_WING_ENCAPS_SEED: [u8; 64] = [
    0x91, 0x02, 0x55, 0x1a, 0x83, 0xe4, 0x6c, 0x7f, 0x20, 0xbb, 0x39, 0xcd, 0x42, 0x5e, 0xa1, 0x08,
    0xd4, 0x67, 0x72, 0x9f, 0x33, 0x15, 0xfa, 0xe0, 0x6b, 0x88, 0xc1, 0x2d, 0x54, 0x9a, 0x0f, 0x7e,
    0x45, 0x12, 0xc6, 0xf0, 0x7d, 0x93, 0x2a, 0x5b, 0xe8, 0x01, 0x69, 0x34, 0xaf, 0xdc, 0x7b, 0x2e,
    0x19, 0x80, 0x4d, 0xa2, 0x56, 0xf1, 0x63, 0xb9, 0x0c, 0x3a, 0xde, 0x27, 0x74, 0x85, 0x9e, 0x11,
];
const P256_SECRET: [u8; 32] = [
    0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf, 0xee,
    0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91, 0xc3, 0x44,
];
const P256_PEER_SECRET: [u8; 32] = [
    0x6a, 0x10, 0x45, 0xf2, 0x33, 0x9e, 0x80, 0x12, 0xab, 0x74, 0xc6, 0x28, 0xde, 0x91, 0x07, 0x5b,
    0x49, 0xef, 0x32, 0x18, 0x84, 0x2d, 0xbc, 0x60, 0x13, 0xa5, 0x77, 0xc9, 0x0e, 0x4b, 0x26, 0xd1,
];
const P384_SECRET: [u8; 48] = [
    0x5d, 0x8f, 0x61, 0x2a, 0x94, 0xc0, 0x36, 0x77, 0x1b, 0xe2, 0x50, 0xae, 0x47, 0x9c, 0x03, 0xd1,
    0x62, 0x7a, 0xb4, 0xee, 0x88, 0x21, 0x09, 0x35, 0xf0, 0x44, 0xca, 0x7d, 0x19, 0x83, 0xb6, 0x52,
    0x0f, 0xd9, 0x70, 0x2b, 0xac, 0x58, 0x13, 0xe6, 0x74, 0x91, 0x22, 0xcf, 0x3a, 0xbd, 0x55, 0x08,
];
const P521_SECRET: [u8; 66] = [
    0x01, 0x2b, 0x7c, 0x3d, 0x94, 0x58, 0xe1, 0x0f, 0x73, 0xa6, 0xc2, 0x19, 0x4d, 0x80, 0xb5, 0xee,
    0x35, 0x6a, 0x09, 0xdc, 0x41, 0x97, 0xf2, 0x6e, 0x18, 0xab, 0xc5, 0x00, 0x7d, 0x23, 0x59, 0x84,
    0xef, 0x12, 0x48, 0xb0, 0x6c, 0xd7, 0x31, 0x9a, 0x05, 0xfe, 0x62, 0x8b, 0x44, 0xd1, 0x76, 0x20,
    0xba, 0x3f, 0x99, 0x0e, 0x52, 0xc8, 0x14, 0xa7, 0x6d, 0x28, 0xf3, 0x45, 0x8c, 0x01, 0xb9, 0x6f,
    0x33, 0x5a,
];
const ED25519_SECRET: [u8; 32] = [
    0x9b, 0x71, 0x23, 0x55, 0xc4, 0x6a, 0x08, 0x9f, 0x41, 0x82, 0x70, 0x18, 0x52, 0xcd, 0xef, 0x43,
    0x22, 0x11, 0x6d, 0xa0, 0x7e, 0x39, 0x4a, 0xbc, 0xd8, 0x5f, 0x13, 0x26, 0x92, 0xa1, 0xbe, 0x77,
];
const SECP256K1_SECRET: [u8; 32] = [
    0x4e, 0x39, 0x0c, 0x72, 0xa5, 0xd1, 0x5f, 0x20, 0x99, 0x63, 0x81, 0x2e, 0x37, 0xaf, 0x04, 0xbc,
    0xe1, 0x56, 0x48, 0x9a, 0x2f, 0x73, 0x0d, 0x84, 0x51, 0xc6, 0x3b, 0x09, 0xf5, 0x28, 0x61, 0x7d,
];
const BIP340_SCHNORR_SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];
const BIP340_SCHNORR_AUX_RAND: [u8; 32] = [0u8; 32];
const BIP340_SCHNORR_MESSAGE: [u8; 32] = [0u8; 32];
const X25519_SECRET: [u8; 32] = [
    0x13, 0xb4, 0x0e, 0x43, 0x43, 0x29, 0xc8, 0x39, 0x59, 0x22, 0xa6, 0x6d, 0x6f, 0xb8, 0xc5, 0x0d,
    0x3b, 0x35, 0x26, 0x3f, 0x8e, 0x5c, 0x06, 0xca, 0xc6, 0x24, 0xa8, 0x65, 0x27, 0xd3, 0xb3, 0x04,
];
const X25519_PEER_SECRET: [u8; 32] = [
    0x73, 0x80, 0x69, 0x39, 0xb0, 0xf9, 0xe8, 0xd2, 0xae, 0x4c, 0x3d, 0x70, 0xa4, 0xb7, 0x25, 0x93,
    0x36, 0x87, 0xd2, 0x85, 0x8c, 0xa5, 0xd0, 0x89, 0x60, 0xa9, 0xe2, 0x54, 0x50, 0xef, 0x50, 0xae,
];
const ML_DSA_44_SEED: [u8; 32] = [
    0x44, 0x91, 0x37, 0xf7, 0x36, 0xf5, 0xf5, 0xa3, 0x5e, 0xb9, 0xf3, 0x7c, 0x1c, 0x88, 0xc2, 0xa0,
    0xbc, 0xf1, 0x8e, 0x75, 0x7f, 0xfb, 0x92, 0x85, 0xab, 0x2c, 0x4c, 0x26, 0xc1, 0x5c, 0x55, 0xf1,
];
const ML_DSA_65_SEED: [u8; 32] = [
    0x65, 0x91, 0x37, 0xf7, 0x36, 0xf5, 0xf5, 0xa3, 0x5e, 0xb9, 0xf3, 0x7c, 0x1c, 0x88, 0xc2, 0xa0,
    0xbc, 0xf1, 0x8e, 0x75, 0x7f, 0xfb, 0x92, 0x85, 0xab, 0x2c, 0x4c, 0x26, 0xc1, 0x5c, 0x55, 0xf1,
];
const ML_DSA_87_SEED: [u8; 32] = [
    0x1e, 0x91, 0x37, 0xf7, 0x36, 0xf5, 0xf5, 0xa3, 0x5e, 0xb9, 0xf3, 0x7c, 0x1c, 0x88, 0xc2, 0xa0,
    0xbc, 0xf1, 0x8e, 0x75, 0x7f, 0xfb, 0x92, 0x85, 0xab, 0x2c, 0x4c, 0x26, 0xc1, 0x5c, 0x55, 0xf1,
];
const SLH_DSA_SHA2_128S_SK_SEED: [u8; SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN] = [
    0x51, 0x4c, 0x48, 0x2d, 0x44, 0x53, 0x41, 0x2d, 0x53, 0x4b, 0x2d, 0x31, 0x32, 0x38, 0x73, 0x01,
];
const SLH_DSA_SHA2_128S_SK_PRF: [u8; SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN] = [
    0x51, 0x4c, 0x48, 0x2d, 0x44, 0x53, 0x41, 0x2d, 0x50, 0x52, 0x46, 0x31, 0x32, 0x38, 0x73, 0x02,
];
const SLH_DSA_SHA2_128S_PK_SEED: [u8; SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN] = [
    0x51, 0x4c, 0x48, 0x2d, 0x44, 0x53, 0x41, 0x2d, 0x50, 0x4b, 0x2d, 0x31, 0x32, 0x38, 0x73, 0x03,
];
const ML_KEM_512_SEED: [u8; 64] = [
    0x51, 0x25, 0x58, 0x7a, 0xd2, 0x79, 0xd7, 0x94, 0x4c, 0x01, 0x22, 0x8f, 0x76, 0x0b, 0x2a, 0x0b,
    0x52, 0x94, 0x82, 0xc0, 0x1c, 0x6f, 0x95, 0x2f, 0x98, 0x22, 0x66, 0x74, 0xb9, 0x1b, 0xff, 0xf4,
    0x32, 0xc3, 0xc3, 0x52, 0x87, 0x41, 0x8c, 0x5e, 0x01, 0xbf, 0x74, 0x1c, 0x15, 0xc0, 0x3a, 0x20,
    0xbb, 0x14, 0xa6, 0x3b, 0x22, 0x99, 0x2d, 0xe1, 0x95, 0xa1, 0x26, 0x88, 0x22, 0x87, 0x3c, 0x1b,
];
const ML_KEM_768_SEED: [u8; 64] = [
    0x8c, 0x25, 0x58, 0x7a, 0xd2, 0x79, 0xd7, 0x94, 0x4c, 0x01, 0x22, 0x8f, 0x76, 0x0b, 0x2a, 0x0b,
    0x52, 0x94, 0x82, 0xc0, 0x1c, 0x6f, 0x95, 0x2f, 0x98, 0x22, 0x66, 0x74, 0xb9, 0x1b, 0xff, 0xf4,
    0x32, 0xc3, 0xc3, 0x52, 0x87, 0x41, 0x8c, 0x5e, 0x01, 0xbf, 0x74, 0x1c, 0x15, 0xc0, 0x3a, 0x20,
    0xbb, 0x14, 0xa6, 0x3b, 0x22, 0x99, 0x2d, 0xe1, 0x95, 0xa1, 0x26, 0x88, 0x22, 0x87, 0x3c, 0x1b,
];
const ML_KEM_1024_SEED: [u8; 64] = [
    0x7a, 0x10, 0xe4, 0x19, 0xda, 0x75, 0x95, 0x32, 0x9e, 0x9a, 0x7b, 0x63, 0x4b, 0x80, 0x0a, 0x42,
    0xb9, 0xd5, 0x19, 0xde, 0x03, 0xb8, 0x89, 0x55, 0x31, 0x7a, 0xee, 0x71, 0x01, 0x19, 0x65, 0x91,
    0x3f, 0x07, 0x28, 0x9a, 0x3c, 0x52, 0x12, 0xc4, 0x6d, 0x4f, 0x20, 0x89, 0x1b, 0x62, 0xac, 0xd0,
    0x41, 0x5d, 0xf2, 0x68, 0x92, 0x33, 0x77, 0x81, 0xe5, 0xc4, 0x28, 0x6a, 0x09, 0x51, 0x6f, 0x2d,
];
const NOBLE_POST_QUANTUM_PACKAGE: &str = "@noble/post-quantum";
const NOBLE_POST_QUANTUM_VERSION: &str = "0.6.1";

type KeypairBytes = (Vec<u8>, Vec<u8>);
type XWingKeypairFn =
    fn(&[u8]) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), crypto_core::CryptoError>;
type XWingEncapsulateFn =
    fn(&[u8], &[u8]) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), crypto_core::CryptoError>;

#[derive(Debug, Error)]
enum VectorGenError {
    #[error("failed to resolve vectors directory")]
    VectorsDirectory,
    #[error("failed to create vectors directory")]
    CreateVectorsDirectory,
    #[error("failed to serialize vector json")]
    SerializeJson,
    #[error("failed to write vector json")]
    WriteJson,
    #[error("failed to decompress P-256 public key")]
    P256Decompress,
    #[error("failed to derive P-256 ECDH vector")]
    P256Ecdh,
    #[error("failed to sign deterministic P-256 vector")]
    P256Sign,
    #[error("P-256 vector signature did not verify")]
    P256SignInvariant,
    #[error("failed to derive deterministic P-256 vector key")]
    P256Keypair,
    #[error("failed to decompress P-384 public key")]
    P384Decompress,
    #[error("failed to derive deterministic P-384 vector key")]
    P384Keypair,
    #[error("failed to sign deterministic P-384 vector")]
    P384Sign,
    #[error("failed to decompress P-521 public key")]
    P521Decompress,
    #[error("failed to derive deterministic P-521 vector key")]
    P521Keypair,
    #[error("failed to sign deterministic P-521 vector")]
    P521Sign,
    #[error("failed to derive deterministic secp256k1 vector key")]
    Secp256k1Keypair,
    #[error("failed to sign or verify secp256k1 ECDSA vector")]
    Secp256k1Sign,
    #[error("failed to compute BIP-340 Schnorr vector")]
    Bip340Schnorr,
    #[error("failed to decode static RSA vector field")]
    RsaVectorDecode,
    #[error("failed to verify RSA vector")]
    RsaVerify,
    #[error("failed to derive deterministic ML-DSA vector key")]
    MlDsaSeed,
    #[error("failed to derive deterministic ML-KEM-512 vector key")]
    MlKem512Seed,
    #[error("failed to derive deterministic ML-KEM-768 vector key")]
    MlKem768Seed,
    #[error("failed to derive deterministic ML-KEM-1024 vector key")]
    MlKem1024Seed,
    #[error("failed to sign ML-DSA vector")]
    MlDsaSign,
    #[error("failed to compute SLH-DSA vector")]
    SlhDsaOperation,
    #[error("failed to build ML-KEM ciphertext for vector")]
    MlKemCiphertext,
    #[error("ML-KEM implicit rejection did not diverge from the valid secret")]
    MlKemImplicitRejection,
    #[error("failed to compute X-Wing vector")]
    XWingOperation,
    #[error("failed to compute HPKE vector")]
    HpkeOperation,
    #[error("failed to sign Ed25519 vector")]
    Ed25519Sign,
    #[error("failed to verify Ed25519 vector")]
    Ed25519Verify,
    #[error("failed to derive X25519 vector")]
    X25519Derive,
    #[error("failed to construct AES-256-GCM key")]
    AesKey,
    #[error("failed to construct AES-256-GCM nonce")]
    AesNonce,
    #[error("failed to encrypt AES-256-GCM vector")]
    AesEncrypt,
    #[error("failed to construct AES-256-GCM ciphertext")]
    AesCiphertext,
    #[error("failed to decrypt AES-256-GCM vector")]
    AesDecrypt,
    #[error("failed to compute AES-256-KW vector")]
    AesKw,
    #[error("failed to compute AES-256-GCM-SIV vector")]
    AesGcmSiv,
    #[error("failed to compute Argon2id vector")]
    Argon2id,
    #[error("failed to construct ChaCha20-Poly1305 key")]
    ChaChaKey,
    #[error("failed to construct ChaCha20-Poly1305 nonce")]
    ChaChaNonce,
    #[error("failed to encrypt ChaCha20-Poly1305 vector")]
    ChaChaEncrypt,
    #[error("failed to construct ChaCha20-Poly1305 ciphertext")]
    ChaChaCiphertext,
    #[error("failed to decrypt ChaCha20-Poly1305 vector")]
    ChaChaDecrypt,
    #[error("failed to construct HMAC key")]
    HmacKey,
    #[error("failed to compute HMAC vector")]
    HmacAuthenticate,
    #[error("failed to compute or match HKDF vector")]
    Hkdf,
    #[error("failed to compute PBKDF2 vector")]
    Pbkdf2,
    #[error("failed to encode multikey vector")]
    MultikeyEncode,
    #[error("failed to resolve multicodec vector")]
    MulticodecLookup,
    #[error("failed to compute JWK vector")]
    JwkEncode,
    #[error("failed to compute JWK multikey vector")]
    JwkMultikeyEncode,
}

#[derive(Serialize)]
struct Manifest {
    vectors: Vec<&'static str>,
    runtime_lanes: Vec<RuntimeLane>,
    post_quantum_oracle: PostQuantumOracle,
}

#[derive(Serialize)]
struct RuntimeLane {
    name: &'static str,
    harness: &'static str,
    status: &'static str,
    algorithms: Vec<&'static str>,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct PostQuantumOracle {
    package: &'static str,
    version: &'static str,
    algorithms: Vec<&'static str>,
}

#[derive(Serialize)]
struct P256Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key_compressed: String,
    public_key_uncompressed: String,
    // ECDSA (ES256) signing material. The Rust and Kotlin package lanes use
    // deterministic ECDSA and must reproduce these exact bytes; platform
    // native lanes may verify this vector without claiming deterministic emit.
    ecdsa_message: String,
    ecdsa_signature_der: String,
    peer_secret_key: String,
    peer_public_key_compressed: String,
    peer_public_key_uncompressed: String,
    shared_secret: String,
}

#[derive(Serialize)]
struct Sec1EcdsaVector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key_compressed: String,
    public_key_uncompressed: String,
    message: String,
    signature_der: String,
}

#[derive(Serialize)]
struct Ed25519Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Serialize)]
struct Secp256k1Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key_compressed: String,
    // ECDSA (ES256K) signing material. The signature is deterministic
    // (RFC 6979), SHA-256 prehashed, and 64-byte compact low-S (BIP 0062);
    // every lane must reproduce these exact bytes.
    ecdsa_message: String,
    ecdsa_signature_compact: String,
}

#[derive(Serialize)]
struct Bip340SchnorrVector {
    alg: &'static str,
    scheme: &'static str,
    curve: &'static str,
    public_key_format: &'static str,
    secret_key: String,
    public_key_xonly: String,
    message: String,
    aux_rand: String,
    signature: String,
}

#[derive(Serialize)]
struct RsaVector {
    alg: &'static str,
    key_format: &'static str,
    public_key_der: String,
    message: String,
    pkcs1v15_sha1_signature: String,
    pkcs1v15_sha256_signature: String,
    pkcs1v15_sha384_signature: String,
    pkcs1v15_sha512_signature: String,
    pss_sha256_mgf1_sha256_salt_len: usize,
    pss_sha256_mgf1_sha256_signature: String,
    pss_sha1_mgf1_sha1_salt_len: usize,
    pss_sha1_mgf1_sha1_signature: String,
    pss_sha384_mgf1_sha384_salt_len: usize,
    pss_sha384_mgf1_sha384_signature: String,
    pss_sha512_mgf1_sha512_salt_len: usize,
    pss_sha512_mgf1_sha512_signature: String,
}

#[derive(Serialize)]
struct X25519Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key: String,
    peer_secret_key: String,
    peer_public_key: String,
    shared_secret: String,
}

#[derive(Serialize)]
struct MlDsaVector {
    alg: &'static str,
    scheme: &'static str,
    secret_key_format: &'static str,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    /// Message signed by `signature`, so every lane signs identical bytes.
    message: String,
    /// Deterministic ML-DSA-87 signature (FIPS 204 deterministic variant,
    /// empty context). Every implementation must reproduce it exactly.
    signature: String,
}

#[derive(Serialize)]
struct SlhDsaVector {
    alg: &'static str,
    scheme: &'static str,
    hash: &'static str,
    parameter_set: &'static str,
    secret_key_format: &'static str,
    keygen_sk_seed: String,
    keygen_sk_prf: String,
    keygen_pk_seed: String,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    secret_key_length: usize,
    message: String,
    signature: String,
    signature_length: usize,
}

#[derive(Serialize)]
struct MlKemVector {
    alg: &'static str,
    scheme: &'static str,
    secret_key_format: &'static str,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    /// 32-byte encapsulation randomness (`m`) driving deterministic
    /// encapsulation, committed so the ciphertext is reproducible.
    encaps_randomness: String,
    /// Ciphertext produced by deterministic encapsulation to `public_key`.
    ciphertext: String,
    /// Shared secret from encapsulating (equals the decapsulation result).
    shared_secret: String,
    /// `ciphertext` with one byte flipped; must trigger FIPS 203 implicit
    /// rejection rather than an error.
    tampered_ciphertext: String,
    /// Pseudorandom shared secret implicit rejection yields for
    /// `tampered_ciphertext`. Deterministic given the secret key, so every
    /// implementation must agree — and it must differ from `shared_secret`.
    tampered_shared_secret: String,
}

/// Deterministic ML-KEM known-answer data for one variant.
struct MlKemKat {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
    tampered_ciphertext: Vec<u8>,
    tampered_shared_secret: Vec<u8>,
}

#[derive(Serialize)]
struct XWingVectors {
    x_wing_768: XWingVector,
    x_wing_1024: XWingVector,
}

#[derive(Serialize)]
struct XWingVector {
    alg: &'static str,
    scheme: &'static str,
    secret_key_format: &'static str,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    encaps_seed: String,
    ciphertext: String,
    ciphertext_length: usize,
    shared_secret: String,
}

#[derive(Serialize)]
struct HpkeVectors {
    p256_sha256_aes256gcm: HpkeVector,
    x25519_sha256_chacha20poly1305: HpkeVector,
}

#[derive(Serialize)]
struct HpkeVector {
    alg: &'static str,
    mode: &'static str,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    recipient_secret_key: String,
    recipient_public_key: String,
    encaps_seed: String,
    info: String,
    aad: String,
    plaintext: String,
    encapsulated_key: String,
    ciphertext: String,
    tampered_ciphertext: String,
}

#[derive(Serialize)]
struct AesGcmVector {
    alg: &'static str,
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext_with_tag: String,
}

#[derive(Serialize)]
struct AesGcmSivVector {
    alg: &'static str,
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext_with_tag: String,
}

#[derive(Serialize)]
struct Argon2idVector {
    alg: &'static str,
    kdf_version: u32,
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
    secret: String,
    salt: String,
    derived_key: String,
}

#[derive(Serialize)]
struct AesKwVector {
    alg: &'static str,
    kek: String,
    key_data: String,
    wrapped_key: String,
}

#[derive(Serialize)]
struct ChaCha20Poly1305Vectors {
    chacha20_poly1305: ChaCha20Poly1305Vector,
    xchacha20_poly1305: ChaCha20Poly1305Vector,
}

#[derive(Serialize)]
struct ChaCha20Poly1305Vector {
    alg: &'static str,
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext_with_tag: String,
}

#[derive(Serialize)]
struct HmacVectors {
    hmac_sha256: HmacVector,
    hmac_sha512: HmacVector,
}

#[derive(Serialize)]
struct HmacVector {
    alg: &'static str,
    key: String,
    message: String,
    tag: String,
}

#[derive(Serialize)]
struct HkdfVector {
    alg: &'static str,
    hash: &'static str,
    ikm: String,
    salt: String,
    info: String,
    output_len: usize,
    okm: String,
}

#[derive(Serialize)]
struct Pbkdf2Vectors {
    pbkdf2_hmac_sha256: Pbkdf2Vector,
    pbkdf2_hmac_sha512: Pbkdf2Vector,
}

#[derive(Serialize)]
struct Pbkdf2Vector {
    alg: &'static str,
    password: String,
    salt: String,
    iterations: u32,
    output_len: usize,
    derived_key: String,
}

#[derive(Serialize)]
struct HashVector {
    message: String,
    sha2_256: String,
    sha2_384: String,
    sha2_512: String,
    sha3_224: String,
    sha3_256: String,
    sha3_384: String,
    sha3_512: String,
}

#[derive(Serialize)]
struct CodecVector {
    raw: String,
    base64url: String,
    multibase_base64url: String,
    multibase_base58btc: String,
    dag_cbor: String,
    dag_cbor_cid: String,
    multicodec_name: &'static str,
    multicodec_alg: &'static str,
    multicodec_prefixes: Vec<CodecPrefixVector>,
    multikey: String,
}

#[derive(Serialize)]
struct CodecPrefixVector {
    name: &'static str,
    alg: &'static str,
    prefix: String,
}

#[derive(Serialize)]
struct JwkVectors {
    vectors: Vec<JwkVector>,
}

#[derive(Serialize)]
struct JwkVector {
    alg: &'static str,
    public_key: String,
    public_key_length: usize,
    kty: &'static str,
    crv: &'static str,
    jwk_jcs: String,
    multikey: Option<String>,
    multikey_status: &'static str,
}

struct GeneratedKeys {
    p256_public: Vec<u8>,
    p256_secret: Vec<u8>,
    p256_peer_public: Vec<u8>,
    p256_peer_secret: Vec<u8>,
    p384_public: Vec<u8>,
    p384_secret: Vec<u8>,
    p521_public: Vec<u8>,
    p521_secret: Vec<u8>,
    ed25519_public: Vec<u8>,
    ed25519_secret: Vec<u8>,
    secp256k1_public: Vec<u8>,
    secp256k1_secret: Vec<u8>,
    x25519_public: Vec<u8>,
    x25519_secret: Vec<u8>,
    x25519_peer_public: Vec<u8>,
    x25519_peer_secret: Vec<u8>,
    ml_dsa_44_public: Vec<u8>,
    ml_dsa_44_secret: Vec<u8>,
    ml_dsa_65_public: Vec<u8>,
    ml_dsa_65_secret: Vec<u8>,
    ml_dsa_87_public: Vec<u8>,
    ml_dsa_87_secret: Vec<u8>,
    slh_dsa_sha2_128s_public: Vec<u8>,
    slh_dsa_sha2_128s_secret: Vec<u8>,
    mlkem512_public: Vec<u8>,
    mlkem512_secret: Vec<u8>,
    mlkem768_public: Vec<u8>,
    mlkem768_secret: Vec<u8>,
    mlkem1024_public: Vec<u8>,
    mlkem1024_secret: Vec<u8>,
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn ensure_dir(dir: &Path) -> Result<(), VectorGenError> {
    fs::create_dir_all(dir).map_err(|_| VectorGenError::CreateVectorsDirectory)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), VectorGenError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| VectorGenError::SerializeJson)?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|_| VectorGenError::WriteJson)
}

fn vectors_dir() -> Result<PathBuf, VectorGenError> {
    let conformance_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = conformance_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(VectorGenError::VectorsDirectory)?;
    Ok(repo_root.join("vectors"))
}

fn derive_ml_dsa_keypair<P: MlDsaParams>(
    seed_bytes: &[u8],
) -> Result<KeypairBytes, VectorGenError> {
    let seed = MlDsaSeed::try_from(seed_bytes).map_err(|_| VectorGenError::MlDsaSeed)?;
    let signing_key = MlDsaSigningKey::<P>::from_seed(&seed);
    let verifying_key = signing_key.verifying_key();

    Ok((
        verifying_key.to_bytes().to_vec(),
        signing_key.to_seed().to_vec(),
    ))
}

fn derive_mlkem512_keypair() -> Result<KeypairBytes, VectorGenError> {
    let seed =
        MlKemSeed::try_from(&ML_KEM_512_SEED[..]).map_err(|_| VectorGenError::MlKem512Seed)?;
    let decapsulation_key = MlKem512DecapsulationKey::from_seed(seed);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    let secret_seed = decapsulation_key.to_bytes();

    Ok((
        public_key.as_slice().to_vec(),
        secret_seed.as_slice().to_vec(),
    ))
}

fn derive_mlkem768_keypair() -> Result<KeypairBytes, VectorGenError> {
    let seed =
        MlKemSeed::try_from(&ML_KEM_768_SEED[..]).map_err(|_| VectorGenError::MlKem768Seed)?;
    let decapsulation_key = MlKem768DecapsulationKey::from_seed(seed);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    let secret_seed = decapsulation_key.to_bytes();

    Ok((
        public_key.as_slice().to_vec(),
        secret_seed.as_slice().to_vec(),
    ))
}

fn derive_mlkem1024_keypair() -> Result<KeypairBytes, VectorGenError> {
    let seed =
        MlKemSeed::try_from(&ML_KEM_1024_SEED[..]).map_err(|_| VectorGenError::MlKem1024Seed)?;
    let decapsulation_key = MlKem1024DecapsulationKey::from_seed(seed);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    let secret_seed = decapsulation_key.to_bytes();

    Ok((
        public_key.as_slice().to_vec(),
        secret_seed.as_slice().to_vec(),
    ))
}

/// Deterministic ML-DSA signature over [`ML_DSA_MESSAGE`], using the
/// FIPS 204 deterministic variant with an empty context — the same mode
/// every runtime lane must reproduce byte-for-byte.
fn sign_ml_dsa_vector<P: MlDsaParams>(seed_bytes: &[u8]) -> Result<Vec<u8>, VectorGenError> {
    let seed = MlDsaSeed::try_from(seed_bytes).map_err(|_| VectorGenError::MlDsaSeed)?;
    let signing_key = MlDsaSigningKey::<P>::from_seed(&seed);
    // `try_sign` is ML-DSA's deterministic, empty-context signing mode, so
    // every runtime lane must reproduce this signature bit-for-bit.
    let signature = MlDsaSigner::try_sign(&signing_key, ML_DSA_MESSAGE)
        .map_err(|_| VectorGenError::MlDsaSign)?;
    Ok(signature.to_bytes().to_vec())
}

fn derive_slh_dsa_sha2_128s_vector_keypair() -> Result<KeypairBytes, VectorGenError> {
    let (public_key, secret_key) = derive_slh_dsa_sha2_128s_keypair(
        &SLH_DSA_SHA2_128S_SK_SEED,
        &SLH_DSA_SHA2_128S_SK_PRF,
        &SLH_DSA_SHA2_128S_PK_SEED,
    )
    .map_err(|_| VectorGenError::SlhDsaOperation)?;

    Ok((public_key, secret_key.to_vec()))
}

fn sign_slh_dsa_sha2_128s_vector(secret_key: &[u8]) -> Result<Vec<u8>, VectorGenError> {
    sign_slh_dsa_sha2_128s(secret_key, SLH_DSA_MESSAGE).map_err(|_| VectorGenError::SlhDsaOperation)
}

/// One byte flipped in a copy of `ciphertext`, used to exercise ML-KEM
/// implicit rejection.
fn tamper_first_byte(ciphertext: &[u8]) -> Vec<u8> {
    let mut tampered = ciphertext.to_vec();
    if let Some(first) = tampered.first_mut() {
        *first ^= 0x01;
    }
    tampered
}

/// Computes the deterministic ML-KEM-512 known-answer data: encapsulate to
/// the vector public key with fixed randomness, then decapsulate a tampered
/// ciphertext to capture the implicit-rejection secret.
fn mlkem512_kat(secret_seed: &[u8]) -> Result<MlKemKat, VectorGenError> {
    let seed = MlKemSeed::try_from(secret_seed).map_err(|_| VectorGenError::MlKem512Seed)?;
    let decapsulation_key = MlKem512DecapsulationKey::from_seed(seed);
    let randomness = MlKemB32::try_from(&ML_KEM_ENCAPS_RANDOMNESS[..])
        .map_err(|_| VectorGenError::MlKem512Seed)?;

    let (ciphertext, shared_secret) = decapsulation_key
        .encapsulation_key()
        .encapsulate_deterministic(&randomness);
    let ciphertext = ciphertext.as_slice().to_vec();
    let shared_secret = shared_secret.as_slice().to_vec();

    let tampered_ciphertext = tamper_first_byte(&ciphertext);
    let tampered = MlKem512Ciphertext::try_from(tampered_ciphertext.as_slice())
        .map_err(|_| VectorGenError::MlKemCiphertext)?;
    let tampered_shared_secret = decapsulation_key.decapsulate(&tampered).as_slice().to_vec();
    if tampered_shared_secret == shared_secret {
        return Err(VectorGenError::MlKemImplicitRejection);
    }

    Ok(MlKemKat {
        ciphertext,
        shared_secret,
        tampered_ciphertext,
        tampered_shared_secret,
    })
}

/// ML-KEM-768 counterpart of [`mlkem512_kat`].
fn mlkem768_kat(secret_seed: &[u8]) -> Result<MlKemKat, VectorGenError> {
    let seed = MlKemSeed::try_from(secret_seed).map_err(|_| VectorGenError::MlKem768Seed)?;
    let decapsulation_key = MlKem768DecapsulationKey::from_seed(seed);
    let randomness = MlKemB32::try_from(&ML_KEM_ENCAPS_RANDOMNESS[..])
        .map_err(|_| VectorGenError::MlKem768Seed)?;

    let (ciphertext, shared_secret) = decapsulation_key
        .encapsulation_key()
        .encapsulate_deterministic(&randomness);
    let ciphertext = ciphertext.as_slice().to_vec();
    let shared_secret = shared_secret.as_slice().to_vec();

    let tampered_ciphertext = tamper_first_byte(&ciphertext);
    let tampered = MlKem768Ciphertext::try_from(tampered_ciphertext.as_slice())
        .map_err(|_| VectorGenError::MlKemCiphertext)?;
    let tampered_shared_secret = decapsulation_key.decapsulate(&tampered).as_slice().to_vec();
    if tampered_shared_secret == shared_secret {
        return Err(VectorGenError::MlKemImplicitRejection);
    }

    Ok(MlKemKat {
        ciphertext,
        shared_secret,
        tampered_ciphertext,
        tampered_shared_secret,
    })
}

/// ML-KEM-1024 counterpart of [`mlkem768_kat`].
fn mlkem1024_kat(secret_seed: &[u8]) -> Result<MlKemKat, VectorGenError> {
    let seed = MlKemSeed::try_from(secret_seed).map_err(|_| VectorGenError::MlKem1024Seed)?;
    let decapsulation_key = MlKem1024DecapsulationKey::from_seed(seed);
    let randomness = MlKemB32::try_from(&ML_KEM_ENCAPS_RANDOMNESS[..])
        .map_err(|_| VectorGenError::MlKem1024Seed)?;

    let (ciphertext, shared_secret) = decapsulation_key
        .encapsulation_key()
        .encapsulate_deterministic(&randomness);
    let ciphertext = ciphertext.as_slice().to_vec();
    let shared_secret = shared_secret.as_slice().to_vec();

    let tampered_ciphertext = tamper_first_byte(&ciphertext);
    let tampered = MlKem1024Ciphertext::try_from(tampered_ciphertext.as_slice())
        .map_err(|_| VectorGenError::MlKemCiphertext)?;
    let tampered_shared_secret = decapsulation_key.decapsulate(&tampered).as_slice().to_vec();
    if tampered_shared_secret == shared_secret {
        return Err(VectorGenError::MlKemImplicitRejection);
    }

    Ok(MlKemKat {
        ciphertext,
        shared_secret,
        tampered_ciphertext,
        tampered_shared_secret,
    })
}

fn generate_keys() -> Result<GeneratedKeys, VectorGenError> {
    let p256_secret_key =
        P256SecretKey::from_slice(&P256_SECRET).map_err(|_| VectorGenError::P256Keypair)?;
    let p256_signing_key = P256SigningKey::from(&p256_secret_key);
    let p256_public = p256_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p256_secret = p256_secret_key.to_bytes().to_vec();
    let p256_peer_secret_key =
        P256SecretKey::from_slice(&P256_PEER_SECRET).map_err(|_| VectorGenError::P256Keypair)?;
    let p256_peer_signing_key = P256SigningKey::from(&p256_peer_secret_key);
    let p256_peer_public = p256_peer_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p256_peer_secret = p256_peer_secret_key.to_bytes().to_vec();

    let p384_secret_key =
        P384SecretKey::from_slice(&P384_SECRET).map_err(|_| VectorGenError::P384Keypair)?;
    let p384_signing_key = P384SigningKey::from(&p384_secret_key);
    let p384_public = p384_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p384_secret = p384_secret_key.to_bytes().to_vec();

    let p521_secret_key =
        P521SecretKey::from_slice(&P521_SECRET).map_err(|_| VectorGenError::P521Keypair)?;
    let p521_signing_key = P521SigningKey::from(&p521_secret_key);
    let p521_public = p521_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p521_secret = p521_secret_key.to_bytes().to_vec();

    let ed25519_signing_key = Ed25519SigningKey::from_bytes(&ED25519_SECRET);
    let ed25519_public = ed25519_signing_key.verifying_key().to_bytes().to_vec();
    let ed25519_secret = ED25519_SECRET.to_vec();

    let secp256k1_signing_key = Secp256k1SigningKey::from_slice(&SECP256K1_SECRET)
        .map_err(|_| VectorGenError::Secp256k1Keypair)?;
    let secp256k1_public = secp256k1_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let secp256k1_secret = SECP256K1_SECRET.to_vec();

    let x25519_secret_key = X25519StaticSecret::from(X25519_SECRET);
    let x25519_public_key = X25519PublicKey::from(&x25519_secret_key);
    let x25519_peer_secret_key = X25519StaticSecret::from(X25519_PEER_SECRET);
    let x25519_peer_public_key = X25519PublicKey::from(&x25519_peer_secret_key);
    let x25519_public = x25519_public_key.as_bytes().to_vec();
    let x25519_secret = X25519_SECRET.to_vec();
    let x25519_peer_public = x25519_peer_public_key.as_bytes().to_vec();
    let x25519_peer_secret = X25519_PEER_SECRET.to_vec();
    let (ml_dsa_44_public, ml_dsa_44_secret) = derive_ml_dsa_keypair::<MlDsa44>(&ML_DSA_44_SEED)?;
    let (ml_dsa_65_public, ml_dsa_65_secret) = derive_ml_dsa_keypair::<MlDsa65>(&ML_DSA_65_SEED)?;
    let (ml_dsa_87_public, ml_dsa_87_secret) = derive_ml_dsa_keypair::<MlDsa87>(&ML_DSA_87_SEED)?;
    let (slh_dsa_sha2_128s_public, slh_dsa_sha2_128s_secret) =
        derive_slh_dsa_sha2_128s_vector_keypair()?;
    let (mlkem512_public, mlkem512_secret) = derive_mlkem512_keypair()?;
    let (mlkem768_public, mlkem768_secret) = derive_mlkem768_keypair()?;
    let (mlkem1024_public, mlkem1024_secret) = derive_mlkem1024_keypair()?;

    Ok(GeneratedKeys {
        p256_public,
        p256_secret,
        p256_peer_public,
        p256_peer_secret,
        p384_public,
        p384_secret,
        p521_public,
        p521_secret,
        ed25519_public,
        ed25519_secret,
        secp256k1_public,
        secp256k1_secret,
        x25519_public,
        x25519_secret,
        x25519_peer_public,
        x25519_peer_secret,
        ml_dsa_44_public,
        ml_dsa_44_secret,
        ml_dsa_65_public,
        ml_dsa_65_secret,
        ml_dsa_87_public,
        ml_dsa_87_secret,
        slh_dsa_sha2_128s_public,
        slh_dsa_sha2_128s_secret,
        mlkem512_public,
        mlkem512_secret,
        mlkem768_public,
        mlkem768_secret,
        mlkem1024_public,
        mlkem1024_secret,
    })
}

fn write_key_vectors(dir: &Path, keys: &GeneratedKeys) -> Result<(), VectorGenError> {
    let p256_uncompressed =
        decompress_p256(&keys.p256_public).map_err(|_| VectorGenError::P256Decompress)?;
    let p256_peer_uncompressed =
        decompress_p256(&keys.p256_peer_public).map_err(|_| VectorGenError::P256Decompress)?;
    let p256_shared_secret = derive_p256_shared_secret(&keys.p256_secret, &keys.p256_peer_public)
        .map_err(|_| VectorGenError::P256Ecdh)?;
    let p256_peer_shared_secret =
        derive_p256_shared_secret(&keys.p256_peer_secret, &keys.p256_public)
            .map_err(|_| VectorGenError::P256Ecdh)?;
    if p256_shared_secret.as_slice() != p256_peer_shared_secret.as_slice() {
        return Err(VectorGenError::P256Ecdh);
    }
    let p256_signature = sign_p256_der_prehash(&keys.p256_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::P256Sign)?;
    verify_p256_der_prehash(&p256_signature, SIGNATURE_MESSAGE, &p256_uncompressed)
        .map_err(|_| VectorGenError::P256SignInvariant)?;
    write_json(
        &dir.join("p256.json"),
        &P256Vector {
            alg: "ES256",
            curve: "P-256",
            secret_key: b64u(&keys.p256_secret),
            public_key_compressed: b64u(&keys.p256_public),
            public_key_uncompressed: b64u(&p256_uncompressed),
            ecdsa_message: b64u(SIGNATURE_MESSAGE),
            ecdsa_signature_der: b64u(&p256_signature),
            peer_secret_key: b64u(&keys.p256_peer_secret),
            peer_public_key_compressed: b64u(&keys.p256_peer_public),
            peer_public_key_uncompressed: b64u(&p256_peer_uncompressed),
            shared_secret: b64u(p256_shared_secret.as_slice()),
        },
    )?;

    let p384_uncompressed =
        decompress_p384(&keys.p384_public).map_err(|_| VectorGenError::P384Decompress)?;
    let p384_signature = sign_p384_der_prehash(&keys.p384_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::P384Sign)?;
    write_json(
        &dir.join("p384.json"),
        &Sec1EcdsaVector {
            alg: "ES384",
            curve: "P-384",
            secret_key: b64u(&keys.p384_secret),
            public_key_compressed: b64u(&keys.p384_public),
            public_key_uncompressed: b64u(&p384_uncompressed),
            message: b64u(SIGNATURE_MESSAGE),
            signature_der: b64u(&p384_signature),
        },
    )?;

    let p521_uncompressed =
        decompress_p521(&keys.p521_public).map_err(|_| VectorGenError::P521Decompress)?;
    let p521_signature = sign_p521_der_prehash(&keys.p521_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::P521Sign)?;
    write_json(
        &dir.join("p521.json"),
        &Sec1EcdsaVector {
            alg: "ES512",
            curve: "P-521",
            secret_key: b64u(&keys.p521_secret),
            public_key_compressed: b64u(&keys.p521_public),
            public_key_uncompressed: b64u(&p521_uncompressed),
            message: b64u(SIGNATURE_MESSAGE),
            signature_der: b64u(&p521_signature),
        },
    )?;

    let ed25519_signature = sign_ed25519(&keys.ed25519_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::Ed25519Sign)?;
    verify_ed25519(&keys.ed25519_public, SIGNATURE_MESSAGE, &ed25519_signature)
        .map_err(|_| VectorGenError::Ed25519Verify)?;

    write_json(
        &dir.join("ed25519.json"),
        &Ed25519Vector {
            alg: "EdDSA",
            curve: "Ed25519",
            secret_key: b64u(&keys.ed25519_secret),
            public_key: b64u(&keys.ed25519_public),
            message: b64u(SIGNATURE_MESSAGE),
            signature: b64u(&ed25519_signature),
        },
    )?;

    let secp256k1_signature = sign_secp256k1(&keys.secp256k1_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::Secp256k1Sign)?;
    // Refuse to emit a signature that does not verify (verify enforces low-S).
    verify_secp256k1(
        &secp256k1_signature,
        SIGNATURE_MESSAGE,
        &keys.secp256k1_public,
    )
    .map_err(|_| VectorGenError::Secp256k1Sign)?;
    write_json(
        &dir.join("secp256k1.json"),
        &Secp256k1Vector {
            alg: "ES256K",
            curve: "secp256k1",
            secret_key: b64u(&keys.secp256k1_secret),
            public_key_compressed: b64u(&keys.secp256k1_public),
            ecdsa_message: b64u(SIGNATURE_MESSAGE),
            ecdsa_signature_compact: b64u(&secp256k1_signature),
        },
    )?;

    let bip340_public_key = derive_bip340_schnorr_public_key(&BIP340_SCHNORR_SECRET)
        .map_err(|_| VectorGenError::Bip340Schnorr)?;
    let bip340_signature = sign_bip340_schnorr(
        &BIP340_SCHNORR_SECRET,
        &BIP340_SCHNORR_MESSAGE,
        &BIP340_SCHNORR_AUX_RAND,
    )
    .map_err(|_| VectorGenError::Bip340Schnorr)?;
    verify_bip340_schnorr(
        &bip340_signature,
        &BIP340_SCHNORR_MESSAGE,
        &bip340_public_key,
    )
    .map_err(|_| VectorGenError::Bip340Schnorr)?;
    write_json(
        &dir.join("bip340_schnorr.json"),
        &Bip340SchnorrVector {
            alg: "BIP-340",
            scheme: "BIP-340 Schnorr",
            curve: "secp256k1",
            public_key_format: "x-only",
            secret_key: b64u(&BIP340_SCHNORR_SECRET),
            public_key_xonly: b64u(&bip340_public_key),
            message: b64u(&BIP340_SCHNORR_MESSAGE),
            aux_rand: b64u(&BIP340_SCHNORR_AUX_RAND),
            signature: b64u(&bip340_signature),
        },
    )?;

    write_rsa_vector(dir)?;

    let x25519_shared_secret =
        derive_x25519_shared_secret(&keys.x25519_secret, &keys.x25519_peer_public)
            .map_err(|_| VectorGenError::X25519Derive)?;
    let x25519_peer_shared_secret =
        derive_x25519_shared_secret(&keys.x25519_peer_secret, &keys.x25519_public)
            .map_err(|_| VectorGenError::X25519Derive)?;
    if x25519_shared_secret != x25519_peer_shared_secret {
        return Err(VectorGenError::X25519Derive);
    }

    write_json(
        &dir.join("x25519.json"),
        &X25519Vector {
            alg: "X25519",
            curve: "X25519",
            secret_key: b64u(&keys.x25519_secret),
            public_key: b64u(&keys.x25519_public),
            peer_secret_key: b64u(&keys.x25519_peer_secret),
            peer_public_key: b64u(&keys.x25519_peer_public),
            shared_secret: b64u(&x25519_shared_secret),
        },
    )?;

    let ml_dsa_44_signature = sign_ml_dsa_vector::<MlDsa44>(&ML_DSA_44_SEED)?;
    write_json(
        &dir.join("ml_dsa_44.json"),
        &MlDsaVector {
            alg: "ML-DSA-44",
            scheme: "ML-DSA-44",
            secret_key_format: "fips-204-seed",
            secret_key: b64u(&keys.ml_dsa_44_secret),
            public_key: b64u(&keys.ml_dsa_44_public),
            public_key_length: keys.ml_dsa_44_public.len(),
            message: b64u(ML_DSA_MESSAGE),
            signature: b64u(&ml_dsa_44_signature),
        },
    )?;

    let ml_dsa_65_signature = sign_ml_dsa_vector::<MlDsa65>(&ML_DSA_65_SEED)?;
    write_json(
        &dir.join("ml_dsa_65.json"),
        &MlDsaVector {
            alg: "ML-DSA-65",
            scheme: "ML-DSA-65",
            secret_key_format: "fips-204-seed",
            secret_key: b64u(&keys.ml_dsa_65_secret),
            public_key: b64u(&keys.ml_dsa_65_public),
            public_key_length: keys.ml_dsa_65_public.len(),
            message: b64u(ML_DSA_MESSAGE),
            signature: b64u(&ml_dsa_65_signature),
        },
    )?;

    let ml_dsa_87_signature = sign_ml_dsa_vector::<MlDsa87>(&ML_DSA_87_SEED)?;
    write_json(
        &dir.join("ml_dsa_87.json"),
        &MlDsaVector {
            alg: "ML-DSA-87",
            scheme: "ML-DSA-87",
            secret_key_format: "fips-204-seed",
            secret_key: b64u(&keys.ml_dsa_87_secret),
            public_key: b64u(&keys.ml_dsa_87_public),
            public_key_length: keys.ml_dsa_87_public.len(),
            message: b64u(ML_DSA_MESSAGE),
            signature: b64u(&ml_dsa_87_signature),
        },
    )?;

    let slh_dsa_sha2_128s_signature =
        sign_slh_dsa_sha2_128s_vector(&keys.slh_dsa_sha2_128s_secret)?;
    write_json(
        &dir.join("slh_dsa_sha2_128s.json"),
        &SlhDsaVector {
            alg: "SLH-DSA-SHA2-128s",
            scheme: "SLH-DSA-SHA2-128s",
            hash: "SHA2",
            parameter_set: "128s",
            secret_key_format: "fips-205-serialized-secret-key",
            keygen_sk_seed: b64u(&SLH_DSA_SHA2_128S_SK_SEED),
            keygen_sk_prf: b64u(&SLH_DSA_SHA2_128S_SK_PRF),
            keygen_pk_seed: b64u(&SLH_DSA_SHA2_128S_PK_SEED),
            secret_key: b64u(&keys.slh_dsa_sha2_128s_secret),
            public_key: b64u(&keys.slh_dsa_sha2_128s_public),
            public_key_length: keys.slh_dsa_sha2_128s_public.len(),
            secret_key_length: keys.slh_dsa_sha2_128s_secret.len(),
            message: b64u(SLH_DSA_MESSAGE),
            signature: b64u(&slh_dsa_sha2_128s_signature),
            signature_length: slh_dsa_sha2_128s_signature.len(),
        },
    )?;

    let mlkem512 = mlkem512_kat(&keys.mlkem512_secret)?;
    write_json(
        &dir.join("mlkem512.json"),
        &MlKemVector {
            alg: "ML-KEM-512",
            scheme: "ML-KEM-512",
            secret_key_format: "fips-203-seed",
            secret_key: b64u(&keys.mlkem512_secret),
            public_key: b64u(&keys.mlkem512_public),
            public_key_length: keys.mlkem512_public.len(),
            encaps_randomness: b64u(&ML_KEM_ENCAPS_RANDOMNESS),
            ciphertext: b64u(&mlkem512.ciphertext),
            shared_secret: b64u(&mlkem512.shared_secret),
            tampered_ciphertext: b64u(&mlkem512.tampered_ciphertext),
            tampered_shared_secret: b64u(&mlkem512.tampered_shared_secret),
        },
    )?;

    let mlkem768 = mlkem768_kat(&keys.mlkem768_secret)?;
    write_json(
        &dir.join("mlkem768.json"),
        &MlKemVector {
            alg: "ML-KEM-768",
            scheme: "ML-KEM-768",
            secret_key_format: "fips-203-seed",
            secret_key: b64u(&keys.mlkem768_secret),
            public_key: b64u(&keys.mlkem768_public),
            public_key_length: keys.mlkem768_public.len(),
            encaps_randomness: b64u(&ML_KEM_ENCAPS_RANDOMNESS),
            ciphertext: b64u(&mlkem768.ciphertext),
            shared_secret: b64u(&mlkem768.shared_secret),
            tampered_ciphertext: b64u(&mlkem768.tampered_ciphertext),
            tampered_shared_secret: b64u(&mlkem768.tampered_shared_secret),
        },
    )?;

    let mlkem1024 = mlkem1024_kat(&keys.mlkem1024_secret)?;
    write_json(
        &dir.join("mlkem1024.json"),
        &MlKemVector {
            alg: "ML-KEM-1024",
            scheme: "ML-KEM-1024",
            secret_key_format: "fips-203-seed",
            secret_key: b64u(&keys.mlkem1024_secret),
            public_key: b64u(&keys.mlkem1024_public),
            public_key_length: keys.mlkem1024_public.len(),
            encaps_randomness: b64u(&ML_KEM_ENCAPS_RANDOMNESS),
            ciphertext: b64u(&mlkem1024.ciphertext),
            shared_secret: b64u(&mlkem1024.shared_secret),
            tampered_ciphertext: b64u(&mlkem1024.tampered_ciphertext),
            tampered_shared_secret: b64u(&mlkem1024.tampered_shared_secret),
        },
    )
}

const RSA_PUBLIC_KEY_DER_B64: &str = "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB";
const RSA_MESSAGE_B64: &str = "UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg";
const RSA_PKCS1V15_SHA1_B64: &str = "hA_Xs2jYATVjBo9PtGmi-tr0fVJH57-QmUHvtZp2daMI_xk5XdMu4XYHRhCuP5LpHpjxJr2HvrM1ovdXq8bxfBDQkyR8fQgJcxs9lzCX4e9G5gu-cx1wo-YEoco6OGO6FZRoGHJgiUJ1gp6AbihXQYmzwkP4lJPeZTgTqfCzW9OURB6f-VWbxnWN9ALmIAboMmsMTBcJ4kEVQqK0EH5uRrGqF5R2QONNntmwYLByM3mIwyFGhm5RksGN4Xpz1b140xQLHIg6NdJS9x3okC2PEGyQ0l-1o1ct7yrqsnGcRoDkVLzpXQj_CjBAMQ7Vmmnb0yC11VuzlYBel3RFZM_dpA";
const RSA_PKCS1V15_SHA256_B64: &str = "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw";
const RSA_PKCS1V15_SHA384_B64: &str = "UPPRJw8CyERJsI7PW5_9WbhZmmIe2wie3bt1FuZz_8ShFfgaFXwQfwn_YS4QtkPEAn6q438r05M25U-IYQXaDiisXSocMxRE06nqMvvrCgO6p6O-2_xWW8V8xhDox1aPqWdp54Ba6A0s3dywUe5zQpOAL-xQ8KLIZpIE118xKwhouFMGZBvCNJDDMMVTxIyp-EpThhiE5EFxL5vp9hVx4euaEfgQhw5MXnJmxKW4Pt9sSdMlvoP8aFrW5st9rLfvknJz4EwgIVevM5XYaWsrjZfJOKY5CmCVmvW-evOMjumMRRU9t2OOOf5NHszKzK3qtUvzCbXUz8F1FNFJeZ_GaA";
const RSA_PKCS1V15_SHA512_B64: &str = "MQ0UP3caVxnjq72kvCzRSvEbk2msNM0l76lv84OPjuA7Xu0EAb6H4WjoDnwqCy1aJe0wZQVVXEQyT8ch3AmDsY7_zCYlayZ8147Jno7n7qda8D0d8Q9SWZRK3Ir4HW6Ex5psmZaAhqSMAnku6On8oWIuofGKOOgMVn7AYDeehlh3f5NscqAtrEebrZ47B-d6XDHuyAe4zxsJPbBj0ef1vvRAA6wXnPIJ7Kvmajb8P4N8dCcjwjA7P9VbyZz_fY2HNpyAGAEFkjOO8uo05u30cHn6TLSYTCsKH2PCqkgH_-UEgjgp8IdBl5PzIHYac8wffRQ39G8LMZR07cll8HaPGA";
const RSA_PSS_SHA1_B64: &str = "rM_td9L0bEnDyo8_7wxbYy2R7b-td3ZB69TFvaoFfm3VLBBELVOpYjHzcW3SKoiKkW56qQ8ZhOfCbWabUVvEmi85l0cf1fjX9Uk1n7tLDRjZwQyBGR3LS5JmOI5TpXZCb9d_wzS4F_wo2x_HTix_fkX7aysINa8RBABlkE9SlofwRWpgn7GTGnnc59WPVKuUUfnNEchm683eyUzi78Mfv5sKLgP7odUYMtMsaQsAN25MYrkmfoRKS-RzQKSV0m7NdGawT2JfPVYV-Q5ZwUtgj_n5FmoCqU7N-Rs2OJMojEvbFfMaAdFFDnyK8pblY0Nt-4epH8U6dPriTdtFa2g_Tw";
const RSA_PSS_SHA256_B64: &str = "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw";
const RSA_PSS_SHA384_B64: &str = "MEnKhv7atsfMZOREi-0Ta-jDTPNHW6U1lz0_WgIkvWLJ2fohqgy2nwyBBfU-JtSZrVEaPEbIElu15F0NKHyoNUGU1WY_bwZVVSPCKWIHjbrQwK8whZw3H8NCP9G5zRJhzpFtIYBdG6H4oOzIYHSNvk7_-suOgiaTsSg0eg-ZxXypXYCGBp-mE1iJ4hRYnOVv-_Sbje00qbFCGL6WwP7Jxnucp11p4Plli25GBkggZu1gTGEhGRnU2j9NTZKxbT2Q-MTZ3mTuQohsVvUNMfF6r2ns9FEQIrsApAu2bryJcPVZkulkyBmVTW2XopOFXI-MlkQpmekoLB7ZHP6enlefBQ";
const RSA_PSS_SHA512_B64: &str = "rzU-aGeM1kEp6mvkQgaJ9myGNXyGtP6r18iBfZNEXf0viVvOjL_ebVE2nD3MUEtiPbxD7TAH-4JXfD-STG3BaGDjH0uVu5KCgSPjKRcskEZuOSzhmJ485fP5oc8yRnrl9lIy-RD0ItX5NWU6g40otuC7LmsrH2vWB2KoOKeWQFgCQD_KP8mssSWVuhwml-S3egN8-S6cprMbwHvJsn1KDpWn_pp0gM9FWyNoHqivekcgGJKz0iVcLzHUbxI5lhj51djBuw32bNrU7jB8dQwf847J9ZDr4cAz_vbP5oCTdXOibPG2J0joYR4mpbRgeernoZGxIf44p7HJX75J-WxE0Q";

fn write_rsa_vector(dir: &Path) -> Result<(), VectorGenError> {
    let public_der_bytes = decode_rsa_vector_field(RSA_PUBLIC_KEY_DER_B64)?;
    let message = decode_rsa_vector_field(RSA_MESSAGE_B64)?;
    let pkcs1v15_sha1_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA1_B64)?;
    let pkcs1v15_sha256_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA256_B64)?;
    let pkcs1v15_sha384_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA384_B64)?;
    let pkcs1v15_sha512_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA512_B64)?;
    let pss_sha256_signature = decode_rsa_vector_field(RSA_PSS_SHA256_B64)?;
    let pss_sha1_signature = decode_rsa_vector_field(RSA_PSS_SHA1_B64)?;
    let pss_sha384_signature = decode_rsa_vector_field(RSA_PSS_SHA384_B64)?;
    let pss_sha512_signature = decode_rsa_vector_field(RSA_PSS_SHA512_B64)?;

    let pkcs1v15_cases: [(RsaHash, &[u8]); 4] = [
        (RsaHash::Sha1, &pkcs1v15_sha1_signature),
        (RsaHash::Sha256, &pkcs1v15_sha256_signature),
        (RsaHash::Sha384, &pkcs1v15_sha384_signature),
        (RsaHash::Sha512, &pkcs1v15_sha512_signature),
    ];
    for (hash, signature) in pkcs1v15_cases {
        verify_rsa_pkcs1v15(
            &public_der_bytes,
            RsaPublicKeyDerEncoding::Pkcs1,
            hash,
            &message,
            signature,
        )
        .map_err(|_| VectorGenError::RsaVerify)?;
    }

    let pss_cases: [(RsaHash, usize, &[u8]); 4] = [
        (RsaHash::Sha256, 32, &pss_sha256_signature),
        (RsaHash::Sha1, 20, &pss_sha1_signature),
        (RsaHash::Sha384, 48, &pss_sha384_signature),
        (RsaHash::Sha512, 64, &pss_sha512_signature),
    ];
    for (hash, salt_len, signature) in pss_cases {
        verify_rsa_pss(
            &public_der_bytes,
            RsaPublicKeyDerEncoding::Pkcs1,
            RsaPssParams {
                message_hash: hash,
                mgf1_hash: hash,
                salt_len,
            },
            &message,
            signature,
        )
        .map_err(|_| VectorGenError::RsaVerify)?;
    }

    write_json(
        &dir.join("rsa.json"),
        &RsaVector {
            alg: "RSA",
            key_format: "PKCS1-DER-RSAPublicKey",
            public_key_der: RSA_PUBLIC_KEY_DER_B64.to_owned(),
            message: RSA_MESSAGE_B64.to_owned(),
            pkcs1v15_sha1_signature: RSA_PKCS1V15_SHA1_B64.to_owned(),
            pkcs1v15_sha256_signature: RSA_PKCS1V15_SHA256_B64.to_owned(),
            pkcs1v15_sha384_signature: RSA_PKCS1V15_SHA384_B64.to_owned(),
            pkcs1v15_sha512_signature: RSA_PKCS1V15_SHA512_B64.to_owned(),
            pss_sha256_mgf1_sha256_salt_len: 32,
            pss_sha256_mgf1_sha256_signature: RSA_PSS_SHA256_B64.to_owned(),
            pss_sha1_mgf1_sha1_salt_len: 20,
            pss_sha1_mgf1_sha1_signature: RSA_PSS_SHA1_B64.to_owned(),
            pss_sha384_mgf1_sha384_salt_len: 48,
            pss_sha384_mgf1_sha384_signature: RSA_PSS_SHA384_B64.to_owned(),
            pss_sha512_mgf1_sha512_salt_len: 64,
            pss_sha512_mgf1_sha512_signature: RSA_PSS_SHA512_B64.to_owned(),
        },
    )
}

fn decode_rsa_vector_field(value: &str) -> Result<Vec<u8>, VectorGenError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| VectorGenError::RsaVectorDecode)
}

fn x_wing_vector(
    alg: &'static str,
    keypair: XWingKeypairFn,
    encapsulate: XWingEncapsulateFn,
) -> Result<XWingVector, VectorGenError> {
    let (public_key, secret_key) =
        keypair(&X_WING_SECRET_SEED).map_err(|_| VectorGenError::XWingOperation)?;
    let (ciphertext, shared_secret) = encapsulate(&public_key, &X_WING_ENCAPS_SEED)
        .map_err(|_| VectorGenError::XWingOperation)?;

    Ok(XWingVector {
        alg,
        scheme: alg,
        secret_key_format: "x-wing-seed",
        secret_key: b64u(&secret_key),
        public_key: b64u(&public_key),
        public_key_length: public_key.len(),
        encaps_seed: b64u(&X_WING_ENCAPS_SEED),
        ciphertext: b64u(&ciphertext),
        ciphertext_length: ciphertext.len(),
        shared_secret: b64u(&shared_secret),
    })
}

fn write_x_wing_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("x_wing.json"),
        &XWingVectors {
            x_wing_768: x_wing_vector(
                "X-Wing-768",
                generate_x_wing_768_keypair_derand,
                x_wing_768_encapsulate_derand,
            )?,
            x_wing_1024: x_wing_vector(
                "X-Wing-1024",
                generate_x_wing_1024_keypair_derand,
                x_wing_1024_encapsulate_derand,
            )?,
        },
    )
}

fn hpke_case(
    alg: &'static str,
    suite: HpkeSuite,
    recipient_secret_key: &[u8],
    recipient_public_key: &[u8],
    encaps_seed: &[u8],
) -> Result<HpkeVector, VectorGenError> {
    let sealed = hpke_seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key,
        encapsulation_randomness: encaps_seed,
        info: HPKE_INFO,
        aad: HPKE_AAD,
        plaintext: HPKE_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::HpkeOperation)?;

    let opened = hpke_open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient_secret_key,
        info: HPKE_INFO,
        aad: HPKE_AAD,
        ciphertext: &sealed.ciphertext,
    })
    .map_err(|_| VectorGenError::HpkeOperation)?;
    if opened.plaintext.as_slice() != HPKE_PLAINTEXT {
        return Err(VectorGenError::HpkeOperation);
    }

    let mut tampered_ciphertext = sealed.ciphertext.clone();
    if let Some(first) = tampered_ciphertext.first_mut() {
        *first ^= 0x01;
    }

    Ok(HpkeVector {
        alg,
        mode: "base",
        kem_id: suite.kem_id(),
        kdf_id: suite.kdf_id(),
        aead_id: suite.aead_id(),
        recipient_secret_key: b64u(recipient_secret_key),
        recipient_public_key: b64u(recipient_public_key),
        encaps_seed: b64u(encaps_seed),
        info: b64u(HPKE_INFO),
        aad: b64u(HPKE_AAD),
        plaintext: b64u(HPKE_PLAINTEXT),
        encapsulated_key: b64u(&sealed.encapsulated_key),
        ciphertext: b64u(&sealed.ciphertext),
        tampered_ciphertext: b64u(&tampered_ciphertext),
    })
}

fn write_hpke_vector(dir: &Path, keys: &GeneratedKeys) -> Result<(), VectorGenError> {
    let p256_public =
        decompress_p256(&keys.p256_public).map_err(|_| VectorGenError::P256Decompress)?;
    write_json(
        &dir.join("hpke.json"),
        &HpkeVectors {
            p256_sha256_aes256gcm: hpke_case(
                "HPKE-P256-SHA256-AES256GCM",
                HpkeSuite::P256Sha256Aes256Gcm,
                &keys.p256_secret,
                &p256_public,
                &HPKE_P256_ENCAPS_SEED,
            )?,
            x25519_sha256_chacha20poly1305: hpke_case(
                "HPKE-X25519-SHA256-CHACHA20POLY1305",
                HpkeSuite::X25519Sha256ChaCha20Poly1305,
                &keys.x25519_secret,
                &keys.x25519_public,
                &HPKE_X25519_ENCAPS_SEED,
            )?,
        },
    )
}

fn write_aes_vector(dir: &Path) -> Result<(), VectorGenError> {
    let key = Aes256GcmKey::from_slice(&AES_KEY).map_err(|_| VectorGenError::AesKey)?;
    let nonce = Aes256GcmNonce::from_slice(&AES_NONCE).map_err(|_| VectorGenError::AesNonce)?;
    let ciphertext = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        plaintext: AES_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::AesEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = CiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::AesCiphertext)?;
    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::AesDecrypt)?;

    if decrypted != AES_PLAINTEXT {
        return Err(VectorGenError::AesDecrypt);
    }

    write_json(
        &dir.join("aes256gcm.json"),
        &AesGcmVector {
            alg: "AES-256-GCM",
            key: b64u(&AES_KEY),
            nonce: b64u(&AES_NONCE),
            aad: b64u(AES_AAD),
            plaintext: b64u(AES_PLAINTEXT),
            ciphertext_with_tag: b64u(&ciphertext_bytes),
        },
    )
}

fn write_aes_gcm_siv_vector(dir: &Path) -> Result<(), VectorGenError> {
    let key = Aes256GcmSivKey::from_slice(&GCM_SIV_KEY).map_err(|_| VectorGenError::AesGcmSiv)?;
    let nonce =
        Aes256GcmSivNonce::from_slice(&GCM_SIV_NONCE).map_err(|_| VectorGenError::AesGcmSiv)?;
    let ciphertext = gcm_siv_encrypt(&GcmSivEncryptRequest {
        key: &key,
        nonce,
        aad: GCM_SIV_AAD,
        plaintext: GCM_SIV_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::AesGcmSiv)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = GcmSivCiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::AesGcmSiv)?;
    let decrypted = gcm_siv_decrypt(&GcmSivDecryptRequest {
        key: &key,
        nonce,
        aad: GCM_SIV_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::AesGcmSiv)?;
    if decrypted != GCM_SIV_PLAINTEXT {
        return Err(VectorGenError::AesGcmSiv);
    }

    write_json(
        &dir.join("aes256gcmsiv.json"),
        &AesGcmSivVector {
            alg: "AES-256-GCM-SIV",
            key: b64u(&GCM_SIV_KEY),
            nonce: b64u(&GCM_SIV_NONCE),
            aad: b64u(GCM_SIV_AAD),
            plaintext: b64u(GCM_SIV_PLAINTEXT),
            ciphertext_with_tag: b64u(&ciphertext_bytes),
        },
    )
}

fn write_argon2id_vector(dir: &Path) -> Result<(), VectorGenError> {
    let profile = Argon2Profile::V1;
    let secret =
        Argon2Secret::from_slice(ARGON2ID_SECRET, profile).map_err(|_| VectorGenError::Argon2id)?;
    let salt =
        Argon2Salt::from_slice(&ARGON2ID_SALT, profile).map_err(|_| VectorGenError::Argon2id)?;
    let derived = argon2id_derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt,
    })
    .map_err(|_| VectorGenError::Argon2id)?;

    write_json(
        &dir.join("argon2id.json"),
        &Argon2idVector {
            alg: "Argon2id",
            kdf_version: 1,
            memory_cost_kib: 262_144,
            time_cost: 3,
            parallelism: 1,
            secret: b64u(ARGON2ID_SECRET),
            salt: b64u(&ARGON2ID_SALT),
            derived_key: b64u(derived.as_bytes()),
        },
    )
}

fn write_aes_kw_vector(dir: &Path) -> Result<(), VectorGenError> {
    let kek = Aes256KwKek::from_slice(&AES_KEY).map_err(|_| VectorGenError::AesKw)?;
    let wrapped = aes_kw_wrap_key(&kek, &AES_KW_KEY_DATA).map_err(|_| VectorGenError::AesKw)?;
    let unwrapped =
        aes_kw_unwrap_key(&kek, wrapped.as_bytes()).map_err(|_| VectorGenError::AesKw)?;
    if unwrapped.as_bytes() != AES_KW_KEY_DATA {
        return Err(VectorGenError::AesKw);
    }

    write_json(
        &dir.join("aes256kw.json"),
        &AesKwVector {
            alg: "AES-256-KW",
            kek: b64u(&AES_KEY),
            key_data: b64u(&AES_KW_KEY_DATA),
            wrapped_key: b64u(wrapped.as_bytes()),
        },
    )
}

fn chacha20_poly1305_vector() -> Result<ChaCha20Poly1305Vector, VectorGenError> {
    let key =
        ChaCha20Poly1305Key::from_slice(&CHACHA_KEY).map_err(|_| VectorGenError::ChaChaKey)?;
    let nonce = ChaCha20Poly1305Nonce::from_slice(&CHACHA_NONCE)
        .map_err(|_| VectorGenError::ChaChaNonce)?;
    let ciphertext = chacha_encrypt(&ChaChaEncryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        plaintext: CHACHA_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::ChaChaEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = ChaChaCiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::ChaChaCiphertext)?;
    let decrypted = chacha_decrypt(&ChaChaDecryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::ChaChaDecrypt)?;

    if decrypted != CHACHA_PLAINTEXT {
        return Err(VectorGenError::ChaChaDecrypt);
    }

    Ok(ChaCha20Poly1305Vector {
        alg: "ChaCha20-Poly1305",
        key: b64u(&CHACHA_KEY),
        nonce: b64u(&CHACHA_NONCE),
        aad: b64u(CHACHA_AAD),
        plaintext: b64u(CHACHA_PLAINTEXT),
        ciphertext_with_tag: b64u(&ciphertext_bytes),
    })
}

fn xchacha20_poly1305_vector() -> Result<ChaCha20Poly1305Vector, VectorGenError> {
    let key =
        ChaCha20Poly1305Key::from_slice(&CHACHA_KEY).map_err(|_| VectorGenError::ChaChaKey)?;
    let nonce = XChaCha20Poly1305Nonce::from_slice(&XCHACHA_NONCE)
        .map_err(|_| VectorGenError::ChaChaNonce)?;
    let ciphertext = encrypt_xchacha20_poly1305(&XChaCha20Poly1305EncryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        plaintext: CHACHA_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::ChaChaEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = ChaChaCiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::ChaChaCiphertext)?;
    let decrypted = decrypt_xchacha20_poly1305(&XChaCha20Poly1305DecryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::ChaChaDecrypt)?;

    if decrypted != CHACHA_PLAINTEXT {
        return Err(VectorGenError::ChaChaDecrypt);
    }

    Ok(ChaCha20Poly1305Vector {
        alg: "XChaCha20-Poly1305",
        key: b64u(&CHACHA_KEY),
        nonce: b64u(&XCHACHA_NONCE),
        aad: b64u(CHACHA_AAD),
        plaintext: b64u(CHACHA_PLAINTEXT),
        ciphertext_with_tag: b64u(&ciphertext_bytes),
    })
}

fn write_chacha20_poly1305_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("chacha20poly1305.json"),
        &ChaCha20Poly1305Vectors {
            chacha20_poly1305: chacha20_poly1305_vector()?,
            xchacha20_poly1305: xchacha20_poly1305_vector()?,
        },
    )
}

fn hmac_vector(
    algorithm: MacAlgorithm,
    alg_name: &'static str,
) -> Result<HmacVector, VectorGenError> {
    let key = HmacKey::from_slice(&HMAC_KEY).map_err(|_| VectorGenError::HmacKey)?;
    let tag = hmac_authenticate(algorithm, &key, HMAC_MESSAGE)
        .map_err(|_| VectorGenError::HmacAuthenticate)?;

    Ok(HmacVector {
        alg: alg_name,
        key: b64u(&HMAC_KEY),
        message: b64u(HMAC_MESSAGE),
        tag: b64u(tag.as_bytes()),
    })
}

fn write_hmac_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("hmac.json"),
        &HmacVectors {
            hmac_sha256: hmac_vector(MacAlgorithm::HmacSha256, "HMAC-SHA-256")?,
            hmac_sha512: hmac_vector(MacAlgorithm::HmacSha512, "HMAC-SHA-512")?,
        },
    )
}

// RFC 5869 HKDF-SHA-256 Test Case 1. The workspace `derive` is raw
// (Extract-then-Expand, no domain prefix), so this reproduces the published
// value and is the same output every lane's raw HKDF must produce.
const HKDF_IKM: &[u8] = &[0x0b; 22];
const HKDF_SALT: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];
const HKDF_INFO: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
const HKDF_OKM_RFC5869: [u8; 42] = [
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
];

fn write_hkdf_vector(dir: &Path) -> Result<(), VectorGenError> {
    let ikm = HkdfInputKeyMaterial::from_slice(HKDF_IKM);
    let salt = HkdfSalt::from_slice(HKDF_SALT);
    let info = HkdfInfo::from_slice(HKDF_INFO);
    let output = hkdf_derive::<42>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .map_err(|_| VectorGenError::Hkdf)?;
    // Refuse to emit a vector that does not match the published RFC 5869 value.
    if output.as_bytes() != &HKDF_OKM_RFC5869 {
        return Err(VectorGenError::Hkdf);
    }
    write_json(
        &dir.join("hkdf.json"),
        &HkdfVector {
            alg: "HKDF-SHA256",
            hash: "SHA-256",
            ikm: b64u(HKDF_IKM),
            salt: b64u(HKDF_SALT),
            info: b64u(HKDF_INFO),
            output_len: 42,
            okm: b64u(output.as_bytes()),
        },
    )
}

fn pbkdf2_vector(
    prf: Pbkdf2Prf,
    alg: &'static str,
    output_len: usize,
) -> Result<Pbkdf2Vector, VectorGenError> {
    let password =
        Pbkdf2Password::from_slice(PBKDF2_PASSWORD, prf).map_err(|_| VectorGenError::Pbkdf2)?;
    let salt = Pbkdf2Salt::from_slice(PBKDF2_SALT, prf).map_err(|_| VectorGenError::Pbkdf2)?;
    let iterations =
        Pbkdf2Iterations::from_u32(PBKDF2_ITERATIONS, prf).map_err(|_| VectorGenError::Pbkdf2)?;
    let derived = derive_pbkdf2_key(&Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len,
    })
    .map_err(|_| VectorGenError::Pbkdf2)?;

    Ok(Pbkdf2Vector {
        alg,
        password: b64u(PBKDF2_PASSWORD),
        salt: b64u(PBKDF2_SALT),
        iterations: PBKDF2_ITERATIONS,
        output_len,
        derived_key: b64u(derived.as_bytes()),
    })
}

fn write_pbkdf2_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("pbkdf2.json"),
        &Pbkdf2Vectors {
            pbkdf2_hmac_sha256: pbkdf2_vector(Pbkdf2Prf::HmacSha256, "PBKDF2-HMAC-SHA-256", 32)?,
            pbkdf2_hmac_sha512: pbkdf2_vector(Pbkdf2Prf::HmacSha512, "PBKDF2-HMAC-SHA-512", 64)?,
        },
    )
}

fn write_hash_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("hashes.json"),
        &HashVector {
            message: b64u(HASH_MESSAGE),
            sha2_256: b64u(sha2_256_digest(HASH_MESSAGE).as_bytes()),
            sha2_384: b64u(digest_sha2_384(HASH_MESSAGE).as_bytes()),
            sha2_512: b64u(digest_sha2_512(HASH_MESSAGE).as_bytes()),
            sha3_224: b64u(digest_sha3_224(HASH_MESSAGE).as_bytes()),
            sha3_256: b64u(sha3_256_digest(HASH_MESSAGE).as_bytes()),
            sha3_384: b64u(digest_sha3_384(HASH_MESSAGE).as_bytes()),
            sha3_512: b64u(digest_sha3_512(HASH_MESSAGE).as_bytes()),
        },
    )
}

fn write_codec_vector(dir: &Path, keys: &GeneratedKeys) -> Result<(), VectorGenError> {
    let cbor_value = CborValue::Map(vec![
        ("name".to_owned(), CborValue::String("codec".to_owned())),
        ("payload".to_owned(), CborValue::Bytes(CODEC_BYTES.to_vec())),
        ("version".to_owned(), CborValue::Int(1)),
    ]);
    let dag_cbor = encode_dag_cbor(&cbor_value);
    let dag_cbor_cid = compute_cid_dag_cbor(&dag_cbor);
    let multikey = encode_multikey("ed25519-pub", &keys.ed25519_public)
        .map_err(|_| VectorGenError::MultikeyEncode)?;
    let multicodec =
        lookup_codec_prefix(&[0xed, 0x01, 0u8]).ok_or(VectorGenError::MulticodecLookup)?;
    let multicodec_prefixes = MULTICODEC_TABLE
        .iter()
        .map(|(name, spec)| CodecPrefixVector {
            name,
            alg: spec.alg,
            prefix: b64u(spec.codec),
        })
        .collect();

    write_json(
        &dir.join("codecs.json"),
        &CodecVector {
            raw: b64u(CODEC_BYTES),
            base64url: bytes_to_base64url(CODEC_BYTES),
            multibase_base64url: bytes_to_multibase_base64url(CODEC_BYTES),
            multibase_base58btc: bytes_to_multibase58btc(CODEC_BYTES),
            dag_cbor: b64u(&dag_cbor),
            dag_cbor_cid,
            multicodec_name: multicodec.name,
            multicodec_alg: multicodec.alg,
            multicodec_prefixes,
            multikey,
        },
    )
}

fn jwk_options(key_use: &'static str) -> JwkOptions {
    JwkOptions {
        alg: true,
        use_sig: key_use == "sig",
        use_enc: key_use == "enc",
        kid: None,
    }
}

fn supported_jwk_vector(
    alg: &'static str,
    public_key: &[u8],
    kty: &'static str,
    crv: &'static str,
    jwk_jcs: String,
    jwk: Jwk,
) -> Result<JwkVector, VectorGenError> {
    let multikey = jwk_to_multikey(&jwk).map_err(|_| VectorGenError::JwkMultikeyEncode)?;

    Ok(JwkVector {
        alg,
        public_key: b64u(public_key),
        public_key_length: public_key.len(),
        kty,
        crv,
        jwk_jcs,
        multikey: Some(multikey),
        multikey_status: "supported",
    })
}

fn pending_multicodec_jwk_vector(
    alg: &'static str,
    public_key: &[u8],
    kty: &'static str,
    crv: &'static str,
    jwk_jcs: String,
) -> JwkVector {
    JwkVector {
        alg,
        public_key: b64u(public_key),
        public_key_length: public_key.len(),
        kty,
        crv,
        jwk_jcs,
        multikey: None,
        multikey_status: "multicodec-missing",
    }
}

fn x_wing_public_key(keypair: XWingKeypairFn) -> Result<Vec<u8>, VectorGenError> {
    let (public_key, _secret_key) =
        keypair(&X_WING_SECRET_SEED).map_err(|_| VectorGenError::XWingOperation)?;
    Ok(public_key)
}

fn write_jwk_vector(dir: &Path, keys: &GeneratedKeys) -> Result<(), VectorGenError> {
    let sig_options = jwk_options("sig");
    let enc_options = jwk_options("enc");
    let x_wing_768_public = x_wing_public_key(generate_x_wing_768_keypair_derand)?;
    let x_wing_1024_public = x_wing_public_key(generate_x_wing_1024_keypair_derand)?;

    let vectors = vec![
        supported_jwk_vector(
            "Ed25519",
            &keys.ed25519_public,
            "OKP",
            "Ed25519",
            ed25519_public_key_to_jwk_jcs(&keys.ed25519_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Okp(
                ed25519_public_key_to_jwk(&keys.ed25519_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        supported_jwk_vector(
            "X25519",
            &keys.x25519_public,
            "OKP",
            "X25519",
            x25519_public_key_to_jwk_jcs(&keys.x25519_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Okp(
                x25519_public_key_to_jwk(&keys.x25519_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        supported_jwk_vector(
            "P-256",
            &keys.p256_public,
            "EC",
            "P-256",
            p256_public_key_to_jwk_jcs(&keys.p256_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Ec(
                p256_public_key_to_jwk(&keys.p256_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "secp256k1",
            &keys.secp256k1_public,
            "EC",
            "secp256k1",
            secp256k1_public_key_to_jwk_jcs(&keys.secp256k1_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Ec(
                secp256k1_public_key_to_jwk(&keys.secp256k1_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-DSA-44",
            &keys.ml_dsa_44_public,
            "AKP",
            "ML-DSA-44",
            mldsa44_public_key_to_jwk_jcs(&keys.ml_dsa_44_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mldsa44_public_key_to_jwk(&keys.ml_dsa_44_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-DSA-65",
            &keys.ml_dsa_65_public,
            "AKP",
            "ML-DSA-65",
            mldsa65_public_key_to_jwk_jcs(&keys.ml_dsa_65_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mldsa65_public_key_to_jwk(&keys.ml_dsa_65_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-DSA-87",
            &keys.ml_dsa_87_public,
            "AKP",
            "ML-DSA-87",
            mldsa87_public_key_to_jwk_jcs(&keys.ml_dsa_87_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mldsa87_public_key_to_jwk(&keys.ml_dsa_87_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        supported_jwk_vector(
            "ML-KEM-512",
            &keys.mlkem512_public,
            "AKP",
            "ML-KEM-512",
            mlkem512_public_key_to_jwk_jcs(&keys.mlkem512_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mlkem512_public_key_to_jwk(&keys.mlkem512_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-KEM-768",
            &keys.mlkem768_public,
            "AKP",
            "ML-KEM-768",
            mlkem768_public_key_to_jwk_jcs(&keys.mlkem768_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mlkem768_public_key_to_jwk(&keys.mlkem768_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-KEM-1024",
            &keys.mlkem1024_public,
            "AKP",
            "ML-KEM-1024",
            mlkem1024_public_key_to_jwk_jcs(&keys.mlkem1024_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mlkem1024_public_key_to_jwk(&keys.mlkem1024_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        pending_multicodec_jwk_vector(
            "SLH-DSA-SHA2-128s",
            &keys.slh_dsa_sha2_128s_public,
            "AKP",
            "SLH-DSA-SHA2-128s",
            slh_dsa_sha2_128s_public_key_to_jwk_jcs(&keys.slh_dsa_sha2_128s_public, sig_options)
                .map_err(|_| VectorGenError::JwkEncode)?,
        ),
        pending_multicodec_jwk_vector(
            "X-Wing-768",
            &x_wing_768_public,
            "AKP",
            "X-Wing-768",
            x_wing_768_public_key_to_jwk_jcs(&x_wing_768_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
        ),
        pending_multicodec_jwk_vector(
            "X-Wing-1024",
            &x_wing_1024_public,
            "AKP",
            "X-Wing-1024",
            x_wing_1024_public_key_to_jwk_jcs(&x_wing_1024_public, enc_options)
                .map_err(|_| VectorGenError::JwkEncode)?,
        ),
    ];

    write_json(&dir.join("jwk.json"), &JwkVectors { vectors })
}

fn write_manifest(dir: &Path) -> Result<(), VectorGenError> {
    let manifest = Manifest {
        vectors: vec![
            "p256.json",
            "p384.json",
            "p521.json",
            "ed25519.json",
            "secp256k1.json",
            "bip340_schnorr.json",
            "rsa.json",
            "x25519.json",
            "ml_dsa_44.json",
            "ml_dsa_65.json",
            "ml_dsa_87.json",
            "slh_dsa_sha2_128s.json",
            "mlkem512.json",
            "mlkem768.json",
            "mlkem1024.json",
            "x_wing.json",
            "hpke.json",
            "aes256gcm.json",
            "aes256gcmsiv.json",
            "aes256kw.json",
            "argon2id.json",
            "chacha20poly1305.json",
            "hkdf.json",
            "hmac.json",
            "pbkdf2.json",
            "hashes.json",
            "codecs.json",
            "jwk.json",
        ],
        runtime_lanes: vec![
            RuntimeLane {
                name: "rust-native",
                harness: "cargo nextest run -p crypto-conformance-vectors",
                status: "executable",
                algorithms: vec![
                    "P-256",
                    "P-384",
                    "P-521",
                    "Ed25519",
                    "secp256k1",
                    "BIP-340-Schnorr",
                    "RSA",
                    "X25519",
                    "ML-DSA-44",
                    "ML-DSA-65",
                    "ML-DSA-87",
                    "SLH-DSA-SHA2-128s",
                    "ML-KEM-512",
                    "ML-KEM-768",
                    "ML-KEM-1024",
                    "X-Wing-768",
                    "X-Wing-1024",
                    "HPKE-P256-SHA256-AES256GCM",
                    "HPKE-X25519-SHA256-CHACHA20POLY1305",
                    "AES-256-GCM",
                    "AES-256-KW",
                    "ChaCha20-Poly1305",
                    "XChaCha20-Poly1305",
                    "HMAC-SHA-256",
                    "HMAC-SHA-512",
                    "PBKDF2-HMAC-SHA-256",
                    "PBKDF2-HMAC-SHA-512",
                    "SHA2-256",
                    "SHA2-384",
                    "SHA2-512",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512",
                    "base64url",
                    "multibase",
                    "multicodec",
                    "multikey",
                    "DAG-CBOR",
                    "JWK",
                    "JWK-Multikey",
                ],
                notes: vec!["Rust native is the canonical vector generation lane."],
            },
            RuntimeLane {
                name: "typescript-native-noble",
                harness: "npm run --prefix crates/conformance/vectors verify:ts-native",
                status: "executable",
                algorithms: vec![
                    "P-256",
                    "P-384",
                    "P-521",
                    "Ed25519",
                    "secp256k1",
                    "BIP-340-Schnorr",
                    "RSA",
                    "X25519",
                    "ML-DSA-44",
                    "ML-DSA-65",
                    "ML-DSA-87",
                    "SLH-DSA-SHA2-128s",
                    "ML-KEM-512",
                    "ML-KEM-768",
                    "ML-KEM-1024",
                    "X-Wing-768",
                    "X-Wing-1024",
                    "HPKE-P256-SHA256-AES256GCM",
                    "HPKE-X25519-SHA256-CHACHA20POLY1305",
                    "AES-256-GCM",
                    "AES-256-KW",
                    "ChaCha20-Poly1305",
                    "HMAC-SHA-256",
                    "HMAC-SHA-512",
                    "PBKDF2-HMAC-SHA-256",
                    "PBKDF2-HMAC-SHA-512",
                    "SHA2-256",
                    "SHA2-384",
                    "SHA2-512",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512",
                    "JWK",
                    "JWK-Multikey",
                ],
                notes: vec![
                    "Uses pinned noble packages as independent TypeScript-native oracles.",
                    "Uses Node native crypto for ChaCha20-Poly1305; XChaCha20-Poly1305 is shape-checked in this lane.",
                ],
            },
            RuntimeLane {
                name: "rust-wasm",
                harness: "cargo check -p crypto-conformance-vectors --no-default-features --features wasm --target wasm32-unknown-unknown",
                status: "compile-gated",
                algorithms: vec![
                    "P-256",
                    "P-384",
                    "P-521",
                    "Ed25519",
                    "secp256k1",
                    "BIP-340-Schnorr",
                    "RSA",
                    "X25519",
                    "ML-DSA-44",
                    "ML-DSA-65",
                    "ML-DSA-87",
                    "SLH-DSA-SHA2-128s",
                    "ML-KEM-512",
                    "ML-KEM-768",
                    "ML-KEM-1024",
                    "X-Wing-768",
                    "X-Wing-1024",
                    "HPKE-P256-SHA256-AES256GCM",
                    "HPKE-X25519-SHA256-CHACHA20POLY1305",
                    "AES-256-GCM",
                    "AES-256-KW",
                    "ChaCha20-Poly1305",
                    "XChaCha20-Poly1305",
                    "HMAC-SHA-256",
                    "HMAC-SHA-512",
                    "PBKDF2-HMAC-SHA-256",
                    "PBKDF2-HMAC-SHA-512",
                    "SHA2-256",
                    "SHA2-384",
                    "SHA2-512",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512",
                    "JWK",
                    "JWK-Multikey",
                ],
                notes: vec!["Execution requires a wasm test runner; compile gate prevents silent lane drift."],
            },
            RuntimeLane {
                name: "swift-native",
                harness: "swift test --package-path crates/conformance/vectors/platform/swift",
                status: "executable",
                algorithms: vec![
                    "P-256",
                    "P-384",
                    "P-521",
                    "Ed25519",
                    "secp256k1",
                    "BIP-340-Schnorr",
                    "RSA",
                    "X25519",
                    "ML-DSA-44",
                    "ML-DSA-65",
                    "ML-DSA-87",
                    "SLH-DSA-SHA2-128s",
                    "ML-KEM-512",
                    "ML-KEM-768",
                    "ML-KEM-1024",
                    "X-Wing-768",
                    "X-Wing-1024",
                    "HPKE-P256-SHA256-AES256GCM",
                    "HPKE-X25519-SHA256-CHACHA20POLY1305",
                    "AES-256-GCM",
                    "AES-256-KW",
                    "ChaCha20-Poly1305",
                    "HMAC-SHA-256",
                    "HMAC-SHA-512",
                    "PBKDF2-HMAC-SHA-256",
                    "PBKDF2-HMAC-SHA-512",
                    "SHA2-256",
                    "SHA2-384",
                    "SHA2-512",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512",
                    "JWK",
                    "JWK-Multikey",
                ],
                notes: vec![
                    "Uses CryptoKit for Apple-native P-256, Ed25519, X25519, HPKE, AES-256-GCM, ChaCha20-Poly1305, HMAC, and SHA-2 conformance.",
                    "Uses reallyme/CSecp256k1 0.1.0 (Bitcoin Core libsecp256k1 v0.7.1 as an XCFramework Clang module) for secp256k1 conformance.",
                    "Compiles SwiftKyber 3.5.0 and SwiftDilithium 3.6.0 as the Swift-native PQ provider candidates.",
                    "Uses the ReallyMe Rust C ABI for ML-DSA, ML-KEM, SLH-DSA, and SHA3 executable conformance until Swift PQ providers expose the workspace key contract.",
                ],
            },
            RuntimeLane {
                name: "kotlin-native-jvm",
                harness: "cd crates/conformance/vectors/platform/kotlin && ./gradlew test --rerun-tasks",
                status: "executable",
                algorithms: vec![
                    "P-256",
                    "P-384",
                    "P-521",
                    "Ed25519",
                    "secp256k1",
                    "BIP-340-Schnorr",
                    "RSA",
                    "X25519",
                    "ML-DSA-44",
                    "ML-DSA-65",
                    "ML-DSA-87",
                    "SLH-DSA-SHA2-128s",
                    "ML-KEM-512",
                    "ML-KEM-768",
                    "ML-KEM-1024",
                    "X-Wing-768",
                    "X-Wing-1024",
                    "HPKE-P256-SHA256-AES256GCM",
                    "HPKE-X25519-SHA256-CHACHA20POLY1305",
                    "AES-256-GCM",
                    "AES-256-KW",
                    "ChaCha20-Poly1305",
                    "HMAC-SHA-256",
                    "HMAC-SHA-512",
                    "PBKDF2-HMAC-SHA-256",
                    "PBKDF2-HMAC-SHA-512",
                    "SHA2-256",
                    "SHA2-384",
                    "SHA2-512",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512",
                    "JWK",
                    "JWK-Multikey",
                ],
                notes: vec![
                    "Uses JVM JCA/JCE for platform algorithms, including AES-256-GCM, ChaCha20-Poly1305, HMAC, and SHA-2/SHA-3.",
                    "Uses Bouncy Castle bcprov-jdk18on 1.84 for secp256k1, ML-DSA, ML-KEM, and SLH-DSA shape/provider conformance.",
                    "The harness command includes --rerun-tasks so an audit run executes tests instead of accepting Gradle's up-to-date cache.",
                ],
            },
        ],
        post_quantum_oracle: PostQuantumOracle {
            package: NOBLE_POST_QUANTUM_PACKAGE,
            version: NOBLE_POST_QUANTUM_VERSION,
            algorithms: vec![
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "ML-KEM-512",
                "ML-KEM-768",
                "ML-KEM-1024",
            ],
        },
    };

    write_json(&dir.join("manifest.json"), &manifest)
}

fn run() -> Result<(), VectorGenError> {
    let dir = vectors_dir()?;
    ensure_dir(&dir)?;

    let keys = generate_keys()?;
    write_key_vectors(&dir, &keys)?;
    write_aes_vector(&dir)?;
    write_aes_gcm_siv_vector(&dir)?;
    write_argon2id_vector(&dir)?;
    write_aes_kw_vector(&dir)?;
    write_chacha20_poly1305_vector(&dir)?;
    write_x_wing_vector(&dir)?;
    write_hpke_vector(&dir, &keys)?;
    write_hmac_vector(&dir)?;
    write_hkdf_vector(&dir)?;
    write_pbkdf2_vector(&dir)?;
    write_hash_vector(&dir)?;
    write_codec_vector(&dir, &keys)?;
    write_jwk_vector(&dir, &keys)?;
    write_manifest(&dir)
}

fn main() -> Result<(), VectorGenError> {
    run()
}
