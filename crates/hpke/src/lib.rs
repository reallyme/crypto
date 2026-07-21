// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod constants;
#[cfg(feature = "native")]
mod dhkem;
mod error;
#[cfg(feature = "native")]
mod export;
mod identifiers;
#[cfg(feature = "native")]
mod keypair;
#[cfg(feature = "native")]
mod mlkem512;
#[cfg(feature = "native")]
mod random;
#[cfg(feature = "native")]
mod seal;
#[cfg(feature = "native")]
mod secp256k1;
mod types;
mod validation;
#[cfg(feature = "native")]
mod x448;

pub use constants::{
    HPKE_AEAD_AES_128_GCM, HPKE_AEAD_AES_256_GCM, HPKE_AEAD_CHACHA20_POLY1305,
    HPKE_AEAD_EXPORT_ONLY, HPKE_AEAD_NONCE_LEN, HPKE_AEAD_TAG_LEN, HPKE_ENCAPSULATED_KEY_MAX_LEN,
    HPKE_KDF_HKDF_SHA256, HPKE_KDF_HKDF_SHA384, HPKE_KDF_HKDF_SHA512, HPKE_KDF_SHAKE128,
    HPKE_KDF_SHAKE256, HPKE_KDF_TURBO_SHAKE128, HPKE_KDF_TURBO_SHAKE256,
    HPKE_KEM_DHKEM_CP256_HKDF_SHA256, HPKE_KEM_DHKEM_CP384_HKDF_SHA384,
    HPKE_KEM_DHKEM_CP521_HKDF_SHA512, HPKE_KEM_DHKEM_P256_HKDF_SHA256,
    HPKE_KEM_DHKEM_P384_HKDF_SHA384, HPKE_KEM_DHKEM_P521_HKDF_SHA512,
    HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256, HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256,
    HPKE_KEM_DHKEM_X25519_HKDF_SHA256, HPKE_KEM_DHKEM_X448_HKDF_SHA512, HPKE_KEM_ML_KEM_1024,
    HPKE_KEM_ML_KEM_1024_P384, HPKE_KEM_ML_KEM_512, HPKE_KEM_ML_KEM_768, HPKE_KEM_ML_KEM_768_P256,
    HPKE_KEM_X25519_KYBER768_DRAFT00, HPKE_KEM_X_WING, HPKE_MIN_PSK_LEN, HPKE_P256_PRIVATE_KEY_LEN,
    HPKE_P256_PUBLIC_KEY_LEN, HPKE_P384_PRIVATE_KEY_LEN, HPKE_P384_PUBLIC_KEY_LEN,
    HPKE_P521_PRIVATE_KEY_LEN, HPKE_P521_PUBLIC_KEY_LEN, HPKE_PRIVATE_KEY_MAX_LEN,
    HPKE_PUBLIC_KEY_MAX_LEN, HPKE_SECP256K1_PRIVATE_KEY_LEN, HPKE_SECP256K1_PUBLIC_KEY_LEN,
    HPKE_X25519_PRIVATE_KEY_LEN, HPKE_X25519_PUBLIC_KEY_LEN, HPKE_X448_PRIVATE_KEY_LEN,
    HPKE_X448_PUBLIC_KEY_LEN,
};
pub use error::HpkeError;
#[cfg(feature = "native")]
pub use export::{receiver_export, sender_export};
pub use identifiers::{
    HpkeAeadId, HpkeComponentSupport, HpkeKdfId, HpkeKemId, HpkeSuite,
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM, HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM, HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM, HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM, HPKE_MLKEM1024_SHAKE256_AES256GCM,
    HPKE_MLKEM512_HKDF_SHA256_AES128GCM, HPKE_MLKEM768P256_SHAKE256_AES256GCM,
    HPKE_MLKEM768_SHAKE256_AES256GCM, HPKE_REGISTERED_AEADS, HPKE_REGISTERED_KDFS,
    HPKE_REGISTERED_KEMS, HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305,
    MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
};
#[cfg(feature = "native")]
pub use keypair::{derive_keypair, keygen};
#[cfg(all(feature = "native", feature = "test-vectors"))]
pub use seal::seal_base_derand;
#[cfg(feature = "native")]
pub use seal::{open_base, open_psk, seal_base, seal_psk};
#[cfg(feature = "test-vectors")]
pub use types::HpkeDerandSealRequest;
pub use types::{
    HpkeExporterSecret, HpkeKeyPair, HpkeOpenOutput, HpkeOpenRequest, HpkePrivateKeyBytes,
    HpkePskOpenRequest, HpkePskSealRequest, HpkeReceiverExportRequest, HpkeSealOutput,
    HpkeSealRequest, HpkeSenderExportOutput, HpkeSenderExportRequest,
};
