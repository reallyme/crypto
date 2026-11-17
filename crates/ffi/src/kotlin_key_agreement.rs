// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JNI transport for constant-time Rust-owned P-curve key agreement.

use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithm,
    CryptoAlgorithmIdentifier,
};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint};
use jni::EnvUnowned;
use reallyme_crypto::operations::key_agreement;
use zeroize::Zeroizing;

use crate::error_status::{key_agreement_status, key_management_status};
use crate::kotlin_protocol_support::{input, pair, run};

fn algorithm(value: jint) -> Result<Algorithm, CryptoError> {
    let identifier = CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithm::KeyAgreement(value.into())),
    };
    let algorithm = Algorithm::try_from(&identifier)
        .map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    if !matches!(
        algorithm,
        Algorithm::P256 | Algorithm::P384 | Algorithm::P521
    ) {
        return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM);
    }
    Ok(algorithm)
}

/// Generate a keypair through the authoritative operation owner.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustKeyAgreement_generateKeyPairNative<
    'local,
>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    selector: jint,
) -> jbyteArray {
    run(env, key_management_status, |_env| {
        let key_pair = key_agreement::generate_key_pair(algorithm(selector)?)?;
        pair(&key_pair.public_key, &key_pair.secret_key)
    })
}

/// Derive only public bytes, leaving all private-key copies in Rust owners.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustKeyAgreement_derivePublicKeyNative<
    'local,
>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    selector: jint,
    secret: JByteArray<'local>,
) -> jbyteArray {
    run(env, key_management_status, |env| {
        let algorithm = algorithm(selector)?;
        let secret = input(env, &secret)?;
        let key_pair = key_agreement::derive_key_pair(algorithm, &secret)?;
        Ok(Zeroizing::new(key_pair.public_key))
    })
}

/// Agree through Rust's constant-time curve arithmetic and clearing owners.
#[no_mangle]
pub extern "system" fn Java_me_really_crypto_ReallyMeRustKeyAgreement_deriveSharedSecretNative<
    'local,
>(
    env: EnvUnowned<'local>,
    _class: JClass<'local>,
    selector: jint,
    public: JByteArray<'local>,
    secret: JByteArray<'local>,
) -> jbyteArray {
    run(env, key_agreement_status, |env| {
        let algorithm = algorithm(selector)?;
        let public = input(env, &public)?;
        let secret = input(env, &secret)?;
        key_agreement::derive_shared_secret(algorithm, &secret, &public)
    })
}

#[cfg(test)]
#[path = "kotlin_key_agreement_tests.rs"]
mod tests;
