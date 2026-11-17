// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JNI adapters for Rust-owned RFC 9180 HPKE Base operations.

use crypto_core::CryptoError;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint};
use jni::EnvUnowned;
use reallyme_crypto::hpke::{
    HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeOpenRequest, HpkeSealRequest, HpkeSuite,
};
use reallyme_crypto::operations::hpke::{open_base, seal_base};

use crate::error_status::hpke_status;
use crate::kotlin_protocol_support::{hpke_ciphertext, input, pair, run};

fn suite(kem: jint, kdf: jint, aead: jint) -> Result<HpkeSuite, CryptoError> {
    let kem = u16::try_from(kem).map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    let kdf = u16::try_from(kdf).map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    let aead = u16::try_from(aead).map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    let suite = HpkeSuite::new(
        HpkeKemId::try_from(kem)?,
        HpkeKdfId::try_from(kdf)?,
        HpkeAeadId::try_from(aead)?,
    );
    if suite != reallyme_crypto::hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM
        && suite != reallyme_crypto::hpke::HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305
    {
        return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    Ok(suite)
}

/// Seals through the Rust HPKE operation owner.
#[no_mangle]
// JNI mirrors the schema request; explicit byte-array parameters avoid JVM secret objects.
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_hpkeSealNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    kem: jint,
    kdf: jint,
    aead: jint,
    public_key: JByteArray<'local>,
    info: JByteArray<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    run(env, hpke_status, |env| {
        let suite = suite(kem, kdf, aead)?;
        let public_key = input(env, &public_key)?;
        let info = input(env, &info)?;
        let aad = input(env, &aad)?;
        let plaintext = input(env, &plaintext)?;
        let output = seal_base(&HpkeSealRequest {
            suite,
            recipient_public_key: &public_key,
            info: &info,
            aad: &aad,
            plaintext: &plaintext,
        })?;
        pair(&output.encapsulated_key, &output.ciphertext)
    })
}

/// Opens through the Rust HPKE operation owner.
#[no_mangle]
// JNI mirrors the schema request; explicit byte-array parameters avoid JVM secret objects.
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_hpkeOpenNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    kem: jint,
    kdf: jint,
    aead: jint,
    secret: JByteArray<'local>,
    encapsulated_key: JByteArray<'local>,
    info: JByteArray<'local>,
    aad: JByteArray<'local>,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    run(env, hpke_status, |env| {
        let suite = suite(kem, kdf, aead)?;
        let secret = input(env, &secret)?;
        let encapsulated_key = input(env, &encapsulated_key)?;
        let info = input(env, &info)?;
        let aad = input(env, &aad)?;
        let ciphertext = hpke_ciphertext(env, &ciphertext)?;
        let output = open_base(&HpkeOpenRequest {
            suite,
            recipient_private_key: &secret,
            encapsulated_key: &encapsulated_key,
            info: &info,
            aad: &aad,
            ciphertext: &ciphertext,
        })?;
        Ok(output.plaintext)
    })
}

/// Conformance-only HPKE adapter; omitted from release images.
#[cfg(feature = "test-vectors")]
#[no_mangle]
// JNI mirrors the schema request; explicit byte-array parameters avoid JVM secret objects.
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_me_really_crypto_ReallyMeProtocolConformance_hpkeSealNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    kem: jint,
    kdf: jint,
    aead: jint,
    public_key: JByteArray<'local>,
    info: JByteArray<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
    randomness: JByteArray<'local>,
) -> jbyteArray {
    run(env, hpke_status, |env| {
        let suite = suite(kem, kdf, aead)?;
        let public_key = input(env, &public_key)?;
        let info = input(env, &info)?;
        let aad = input(env, &aad)?;
        let plaintext = input(env, &plaintext)?;
        let randomness = input(env, &randomness)?;
        let output = reallyme_crypto::operations::hpke::seal_base_derand(
            &reallyme_crypto::hpke::HpkeDerandSealRequest {
                encapsulation_randomness: &randomness,
                suite,
                recipient_public_key: &public_key,
                info: &info,
                aad: &aad,
                plaintext: &plaintext,
            },
        )?;
        pair(&output.encapsulated_key, &output.ciphertext)
    })
}
