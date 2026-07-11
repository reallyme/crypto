// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum VectorTestError {
    #[error("failed to resolve vectors directory")]
    VectorsDirectory,
    #[error("failed to read vector json")]
    ReadVector,
    #[error("failed to parse vector json")]
    ParseVector,
    #[error("vector json field is missing or has the wrong type")]
    InvalidField,
    #[error("failed to decode base64url field")]
    DecodeBase64Url,
    #[error("failed to decompress P-256 public key")]
    P256Decompress,
    #[error("failed to derive P-256 ECDH vector")]
    P256Ecdh,
    #[error("failed to decompress SEC1 public key")]
    Sec1Decompress,
    #[error("failed to sign ECDSA vector")]
    EcdsaSign,
    #[error("failed to verify ECDSA vector")]
    EcdsaVerify,
    #[error("failed to verify RSA vector")]
    RsaVerify,
    #[error("failed to derive X25519 shared secret")]
    X25519Derive,
    #[error("failed to sign Ed25519 vector")]
    Ed25519Sign,
    #[error("failed to verify Ed25519 vector")]
    Ed25519Verify,
    #[error("BIP-340 Schnorr operation failed")]
    Bip340SchnorrOperation,
    #[error("BIP-340 Schnorr committed vector did not reproduce")]
    Bip340SchnorrMismatch,
    #[error("BIP-340 Schnorr accepted a tampered signature")]
    Bip340SchnorrTamperAccepted,
    #[error("failed to construct AES-256-GCM key")]
    AesKey,
    #[error("failed to construct AES-256-GCM nonce")]
    AesNonce,
    #[error("failed to construct AES-256-GCM ciphertext")]
    AesCiphertext,
    #[error("failed to decrypt AES-256-GCM vector")]
    AesDecrypt,
    #[error("failed to compute AES-256-KW vector")]
    AesKw,
    #[error("AES-256-KW accepted a tampered wrapped key")]
    AesKwTamperAccepted,
    #[error("failed to construct ChaCha20-Poly1305 key")]
    ChaChaKey,
    #[error("failed to construct ChaCha20-Poly1305 nonce")]
    ChaChaNonce,
    #[error("failed to construct ChaCha20-Poly1305 ciphertext")]
    ChaChaCiphertext,
    #[error("failed to decrypt ChaCha20-Poly1305 vector")]
    ChaChaDecrypt,
    #[error("failed to construct HMAC key")]
    HmacKey,
    #[error("failed to compute HMAC vector")]
    HmacAuthenticate,
    #[error("failed to verify HMAC vector")]
    HmacVerify,
    #[error("HMAC accepted a tampered tag")]
    HmacTamperAccepted,
    #[error("failed to compute PBKDF2 vector")]
    Pbkdf2,
    #[error("failed to compute HKDF vector")]
    Hkdf,
    #[error("failed to compute AES-256-GCM-SIV vector")]
    AesGcmSiv,
    #[error("failed to compute Argon2id vector")]
    Argon2id,
    #[error("failed to decode DAG-CBOR vector")]
    CborDecode,
    #[error("failed to parse multibase vector")]
    MultibaseParse,
    #[error("failed to parse multikey vector")]
    MultikeyParse,
    #[error("ML-DSA signing did not reproduce the committed signature")]
    MlDsaSignatureMismatch,
    #[error("ML-DSA accepted a tampered signature")]
    MlDsaTamperAccepted,
    #[error("ML-KEM decapsulation did not reproduce the committed shared secret")]
    MlKemSharedSecretMismatch,
    #[error("ML-KEM implicit rejection did not reproduce the committed secret")]
    MlKemImplicitRejectionMismatch,
    #[error("ML-KEM operation failed")]
    MlKemOperation,
    #[error("X-Wing operation failed")]
    XWingOperation,
    #[error("X-Wing committed vector did not reproduce")]
    XWingMismatch,
    #[error("HPKE operation failed")]
    HpkeOperation,
    #[error("HPKE committed vector did not reproduce")]
    HpkeMismatch,
    #[error("ML-DSA operation failed")]
    MlDsaOperation,
    #[error("SLH-DSA signature did not reproduce the committed signature")]
    SlhDsaSignatureMismatch,
    #[error("SLH-DSA accepted a tampered signature")]
    SlhDsaTamperAccepted,
    #[error("SLH-DSA operation failed")]
    SlhDsaOperation,
    #[error("JWK vector did not reproduce")]
    JwkMismatch,
    #[error("JWK operation failed")]
    JwkOperation,
    #[error("JWK multikey operation failed")]
    JwkMultikeyOperation,
}

fn package_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn vectors_dir() -> Result<PathBuf, VectorTestError> {
    package_dir()
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .map(|repo_root| repo_root.join("vectors"))
        .ok_or(VectorTestError::VectorsDirectory)
}

fn read_json(path: PathBuf) -> Result<Value, VectorTestError> {
    let bytes = fs::read(path).map_err(|_| VectorTestError::ReadVector)?;
    serde_json::from_slice(&bytes).map_err(|_| VectorTestError::ParseVector)
}

pub(crate) fn load(name: &str) -> Result<Value, VectorTestError> {
    read_json(vectors_dir()?.join(name))
}

pub(crate) fn load_package_json(name: &str) -> Result<Value, VectorTestError> {
    read_json(package_dir().join(name))
}

pub(crate) fn field_string<'a>(
    value: &'a Value,
    field_name: &str,
) -> Result<&'a str, VectorTestError> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or(VectorTestError::InvalidField)
}

pub(crate) fn field_array<'a>(
    value: &'a Value,
    field_name: &str,
) -> Result<&'a Vec<Value>, VectorTestError> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or(VectorTestError::InvalidField)
}

pub(crate) fn object_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> Result<&'a Value, VectorTestError> {
    value.get(field_name).ok_or(VectorTestError::InvalidField)
}

pub(crate) fn b64u_to_bytes(s: &str) -> Result<Vec<u8>, VectorTestError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| VectorTestError::DecodeBase64Url)
}
