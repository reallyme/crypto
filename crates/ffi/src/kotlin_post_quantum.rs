// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JNI adapters for the Rust-owned post-quantum operations.

use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithm,
    CryptoAlgorithmIdentifier,
};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint};
use jni::EnvUnowned;
use reallyme_crypto::operations::{kem, signature};
use zeroize::Zeroizing;

use crate::error_status::{
    kem_decapsulation_status, kem_encapsulation_status, key_management_status, sign_status,
    verify_status,
};
use crate::kotlin_protocol_support::{input, pair, run};

fn signature_algorithm(value: jint) -> Result<Algorithm, CryptoError> {
    let identifier = CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithm::Signature(value.into())),
    };
    let algorithm = Algorithm::try_from(&identifier)
        .map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    if !matches!(
        algorithm,
        Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 | Algorithm::SlhDsaSha2_128s
    ) {
        return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    Ok(algorithm)
}

fn kem_algorithm(value: jint) -> Result<Algorithm, CryptoError> {
    let identifier = CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithm::Kem(value.into())),
    };
    Algorithm::try_from(&identifier).map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
}

/// Generates or derives a keypair using the canonical Rust operation owner.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_signatureKeyPairNative<
    'local,
>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    secret: JByteArray<'local>,
) -> jbyteArray {
    run(env, key_management_status, |env| {
        let algorithm = signature_algorithm(algorithm)?;
        let key_pair = if secret.is_null() {
            signature::generate_key_pair(algorithm)?
        } else {
            let secret = input(env, &secret)?;
            signature::derive_key_pair(algorithm, &secret)?
        };
        pair(&key_pair.public_key, &key_pair.secret_key)
    })
}

/// Generates or derives a keypair using the canonical Rust operation owner.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_kemKeyPairNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    secret: JByteArray<'local>,
) -> jbyteArray {
    run(env, key_management_status, |env| {
        let algorithm = kem_algorithm(algorithm)?;
        let key_pair = if secret.is_null() {
            kem::generate_key_pair(algorithm)?
        } else {
            let secret = input(env, &secret)?;
            kem::derive_key_pair(algorithm, &secret)?
        };
        pair(&key_pair.public_key, &key_pair.secret_key)
    })
}

/// Signs through the shared Rust signature operation.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_signNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    secret: JByteArray<'local>,
    message: JByteArray<'local>,
) -> jbyteArray {
    run(env, sign_status, |env| {
        let algorithm = signature_algorithm(algorithm)?;
        let secret = input(env, &secret)?;
        let message = input(env, &message)?;
        signature::sign(algorithm, &secret, &message).map(Zeroizing::new)
    })
}

/// Verifies through the shared Rust signature operation.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_verifyNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    public_key: JByteArray<'local>,
    message: JByteArray<'local>,
    signature_bytes: JByteArray<'local>,
) -> jbyteArray {
    run(env, verify_status, |env| {
        let algorithm = signature_algorithm(algorithm)?;
        let public_key = input(env, &public_key)?;
        let message = input(env, &message)?;
        let signature_bytes = input(env, &signature_bytes)?;
        signature::verify(algorithm, &public_key, &message, &signature_bytes)?;
        Ok(Zeroizing::new(Vec::new()))
    })
}

/// Encapsulates using the shared Rust KEM operation.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_encapsulateNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    public_key: JByteArray<'local>,
) -> jbyteArray {
    run(env, kem_encapsulation_status, |env| {
        let algorithm = kem_algorithm(algorithm)?;
        let public_key = input(env, &public_key)?;
        let encapsulation = kem::encapsulate(algorithm, &public_key)?;
        pair(&encapsulation.ciphertext, &encapsulation.shared_secret)
    })
}

/// Decapsulates using the shared Rust KEM operation.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustProtocols_decapsulateNative<'local>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    ciphertext: JByteArray<'local>,
    secret: JByteArray<'local>,
) -> jbyteArray {
    run(env, kem_decapsulation_status, |env| {
        let algorithm = kem_algorithm(algorithm)?;
        let ciphertext = input(env, &ciphertext)?;
        let secret = input(env, &secret)?;
        kem::decapsulate(algorithm, &ciphertext, &secret)
    })
}

/// Conformance-only deterministic KEM adapter; omitted from release images.
#[cfg(feature = "test-vectors")]
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeProtocolConformance_encapsulateNative<
    'local,
>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    public_key: JByteArray<'local>,
    randomness: JByteArray<'local>,
) -> jbyteArray {
    run(env, kem_encapsulation_status, |env| {
        let algorithm = kem_algorithm(algorithm)?;
        let public_key = input(env, &public_key)?;
        let randomness = input(env, &randomness)?;
        let encapsulation = kem::encapsulate_derand(algorithm, &public_key, &randomness)?;
        pair(&encapsulation.ciphertext, &encapsulation.shared_secret)
    })
}
