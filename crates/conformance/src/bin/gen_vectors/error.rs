// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Error)]
pub(crate) enum VectorGenError {
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
    #[error("failed to construct AES-GCM key")]
    AesKey,
    #[error("failed to construct AES-GCM nonce")]
    AesNonce,
    #[error("failed to encrypt AES-GCM vector")]
    AesEncrypt,
    #[error("failed to construct AES-GCM ciphertext")]
    AesCiphertext,
    #[error("failed to decrypt AES-GCM vector")]
    AesDecrypt,
    #[error("failed to compute JWA Concat KDF vector")]
    ConcatKdf,
    #[error("failed to compute AES-256-KW vector")]
    AesKw,
    #[error("failed to compute KMAC256 vector")]
    Kmac,
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
    #[error("failed to compute JWK vector")]
    JwkEncode,
    #[error("failed to compute JWK multikey vector")]
    JwkMultikeyEncode,
}
