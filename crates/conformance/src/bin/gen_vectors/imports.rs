// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use buffa::{EnumValue, Message, MessageField};
use crypto_aes256_gcm::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
};
use crypto_aes256_gcm_siv::{
    decrypt as gcm_siv_decrypt, encrypt as gcm_siv_encrypt, Aes256GcmSivKey, Aes256GcmSivNonce,
    CiphertextWithTag as GcmSivCiphertextWithTag, DecryptRequest as GcmSivDecryptRequest,
    EncryptRequest as GcmSivEncryptRequest,
};
use crypto_aes_kw::{
    unwrap_key_aes128, unwrap_key_aes192, unwrap_key_aes256, wrap_key_aes128, wrap_key_aes192,
    wrap_key_aes256, Aes128KwKek, Aes192KwKek, Aes256KwKek,
};
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
use crypto_concat_kdf::{
    derive_jwa_concat_kdf_sha256, JwaAlgorithmId, JwaConcatKdfRequest, JwaPartyInfo,
    JwaSharedSecret,
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
use crypto_kmac::{derive_kmac256, Kmac256Key};
use crypto_p256::{
    decompress_p256, derive_p256_shared_secret, sign_p256_der_prehash, verify_p256_der_prehash,
};
use crypto_p384::{decompress_p384, derive_p384_shared_secret, sign_p384_der_prehash};
use crypto_p521::{decompress_p521, derive_p521_shared_secret, sign_p521_der_prehash};
use crypto_pbkdf2::{
    derive_key as derive_pbkdf2_key, Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request,
    Pbkdf2Salt,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    CryptoAlgorithmIdentifier, CryptoHashRequest, CryptoOperationRequest, HashAlgorithm,
};
use crypto_rsa::{
    verify_rsa_pkcs1v15, verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding,
};
use crypto_runtime::operation_contract::{
    process_operation_response, process_operation_response_json,
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
use crypto_x_wing::{generate_x_wing_768_keypair_derand, x_wing_768_encapsulate_derand};
use ed25519_dalek_conformance::SigningKey as Ed25519SigningKey;
use envelopes_jwk::{
    ed25519_public_key_to_jwk, ed25519_public_key_to_jwk_jcs, mldsa44_public_key_to_jwk,
    mldsa44_public_key_to_jwk_jcs, mldsa65_public_key_to_jwk, mldsa65_public_key_to_jwk_jcs,
    mldsa87_public_key_to_jwk, mldsa87_public_key_to_jwk_jcs, mlkem1024_public_key_to_jwk,
    mlkem1024_public_key_to_jwk_jcs, mlkem512_public_key_to_jwk, mlkem512_public_key_to_jwk_jcs,
    mlkem768_public_key_to_jwk, mlkem768_public_key_to_jwk_jcs, p256_public_key_to_jwk,
    p256_public_key_to_jwk_jcs, secp256k1_public_key_to_jwk, secp256k1_public_key_to_jwk_jcs,
    slh_dsa_sha2_128s_public_key_to_jwk_jcs, x25519_public_key_to_jwk,
    x25519_public_key_to_jwk_jcs, x_wing_768_public_key_to_jwk_jcs, Jwk, JwkOptions,
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
