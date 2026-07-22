// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Typed HPKE identifiers, suites, key management, encryption, and exporters.
//!
//! Unsuffixed operation functions preserve the established facade contract and
//! return [`crate::operations::OperationError`]. Protocol adapters that need
//! HPKE-specific failure reasons should call the explicit `*_raw` aliases,
//! which return [`crypto_hpke::HpkeError`] without crossing the operation-error
//! boundary.

pub use crate::operations::hpke::{
    derive_keypair as derive_keypair_operation,
    derive_keypair_from_ikm as derive_keypair_from_ikm_operation, keygen as keygen_operation,
    open_base as open_base_operation, open_psk as open_psk_operation,
    receiver_export as receiver_export_operation, seal_base as seal_base_operation,
    seal_psk as seal_psk_operation, sender_export as sender_export_operation,
    setup_receiver_psk as setup_receiver_psk_operation,
    setup_sender_psk as setup_sender_psk_operation,
};
pub use crate::operations::hpke::{
    derive_keypair, derive_keypair_from_ikm, keygen, open_base, open_psk, receiver_export,
    seal_base, seal_psk, sender_export, setup_receiver_psk, setup_sender_psk, HpkePskSenderContext,
    HpkePskSenderSetupOutput, HpkeReceiverContext, HpkeSenderContext,
    HPKE_OPERATION_MIN_INPUT_KEY_MATERIAL_LEN,
};
pub use crypto_hpke::{
    derive_keypair as derive_keypair_raw, derive_keypair_from_ikm as derive_keypair_from_ikm_raw,
    keygen as keygen_raw, open_base as open_base_raw, open_psk as open_psk_raw,
    receiver_export as receiver_export_raw, seal_base as seal_base_raw, seal_psk as seal_psk_raw,
    sender_export as sender_export_raw, setup_receiver_psk as setup_receiver_psk_raw,
    setup_sender_psk as setup_sender_psk_raw, HpkePskSenderContext as RawHpkePskSenderContext,
    HpkePskSenderSetupOutput as RawHpkePskSenderSetupOutput,
    HpkeReceiverContext as RawHpkeReceiverContext,
};
pub use crypto_hpke::{
    HpkeAeadId, HpkeComponentSupport, HpkeError, HpkeExporterSecret, HpkeKdfId, HpkeKemId,
    HpkeKeyPair, HpkeOpenOutput, HpkeOpenRequest, HpkePrivateKeyBytes, HpkePskIdRef,
    HpkePskOpenRequest, HpkePskReceiverSetupRequest, HpkePskRef, HpkePskSealRequest,
    HpkePskSenderSetupRequest, HpkeReceiverExportRequest, HpkeSealOutput, HpkeSealRequest,
    HpkeSenderContext as RawHpkeSenderContext, HpkeSenderExportOutput, HpkeSenderExportRequest,
    HpkeSuite, HPKE_AEAD_AES_128_GCM, HPKE_AEAD_AES_256_GCM, HPKE_AEAD_CHACHA20_POLY1305,
    HPKE_AEAD_EXPORT_ONLY, HPKE_AEAD_NONCE_LEN, HPKE_AEAD_TAG_LEN,
    HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM, HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
    HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM, HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM,
    HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM, HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
    HPKE_ENCAPSULATED_KEY_MAX_LEN, HPKE_KDF_HKDF_SHA256, HPKE_KDF_HKDF_SHA384,
    HPKE_KDF_HKDF_SHA512, HPKE_KDF_SHAKE128, HPKE_KDF_SHAKE256, HPKE_KDF_TURBO_SHAKE128,
    HPKE_KDF_TURBO_SHAKE256, HPKE_KEM_DHKEM_CP256_HKDF_SHA256, HPKE_KEM_DHKEM_CP384_HKDF_SHA384,
    HPKE_KEM_DHKEM_CP521_HKDF_SHA512, HPKE_KEM_DHKEM_P256_HKDF_SHA256,
    HPKE_KEM_DHKEM_P384_HKDF_SHA384, HPKE_KEM_DHKEM_P521_HKDF_SHA512,
    HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256, HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256,
    HPKE_KEM_DHKEM_X25519_HKDF_SHA256, HPKE_KEM_DHKEM_X448_HKDF_SHA512, HPKE_KEM_ML_KEM_1024,
    HPKE_KEM_ML_KEM_1024_P384, HPKE_KEM_ML_KEM_512, HPKE_KEM_ML_KEM_768, HPKE_KEM_ML_KEM_768_P256,
    HPKE_KEM_X25519_KYBER768_DRAFT00, HPKE_KEM_X_WING, HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
    HPKE_MLKEM1024P384_SHAKE256_AES256GCM, HPKE_MLKEM1024_HKDF_SHA384_AES256GCM,
    HPKE_MLKEM1024_SHAKE256_AES256GCM, HPKE_MLKEM768P256_SHAKE256_AES256GCM,
    HPKE_MLKEM768_SHAKE256_AES256GCM, HPKE_P256_PRIVATE_KEY_LEN, HPKE_P256_PUBLIC_KEY_LEN,
    HPKE_P384_PRIVATE_KEY_LEN, HPKE_P384_PUBLIC_KEY_LEN, HPKE_P521_PRIVATE_KEY_LEN,
    HPKE_P521_PUBLIC_KEY_LEN, HPKE_PRIVATE_KEY_MAX_LEN, HPKE_PUBLIC_KEY_MAX_LEN,
    HPKE_REGISTERED_AEADS, HPKE_REGISTERED_KDFS, HPKE_REGISTERED_KEMS,
    HPKE_SECP256K1_PRIVATE_KEY_LEN, HPKE_SECP256K1_PUBLIC_KEY_LEN, HPKE_X25519_PRIVATE_KEY_LEN,
    HPKE_X25519_PUBLIC_KEY_LEN, HPKE_X448_PRIVATE_KEY_LEN, HPKE_X448_PUBLIC_KEY_LEN,
    HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305, MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
    MLS_192_MLKEM1024_AES256GCM_SHA384_P384, MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
};

#[cfg(feature = "test-vectors")]
pub use crate::operations::hpke::{
    seal_base_derand as seal_base_derand_operation,
    sender_export_derand as sender_export_derand_operation,
};
#[cfg(feature = "test-vectors")]
pub use crypto_hpke::{
    seal_base_derand, seal_base_derand as seal_base_derand_raw, setup_sender_psk_derand,
    setup_sender_psk_derand as setup_sender_psk_derand_raw, HpkeDerandPskSenderSetupRequest,
    HpkeDerandSealRequest, HpkeDerandSenderExportRequest,
};
#[cfg(feature = "test-vectors")]
pub use crypto_hpke::{sender_export_derand, sender_export_derand as sender_export_derand_raw};
