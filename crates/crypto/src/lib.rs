// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! # reallyme-crypto
//!
//! Umbrella crate that re-exports the ReallyMe cryptographic primitives,
//! dispatch and signer abstractions behind one dependency and a consistent
//! feature set.
//!
//! ## Platform lanes
//!
//! Rust exposes two backend lanes selected by Cargo feature and target:
//! `native` (portable Rust) and `wasm` (package-owned Rust compiled for
//! WebAssembly with target-appropriate entropy support).
//! Swift and Kotlin provider selection lives in their package facades; those
//! facades call this Rust workspace through FFI/JNI only for algorithms whose
//! provider policy explicitly selects Rust. A lane never silently falls back to
//! another backend.
//!
//! The canonical contract is not the Rust API by itself. It is the shared set
//! of protobuf/enums, package algorithm identifiers, typed error taxonomy,
//! provider manifest, and conformance vectors. Rust is the reference
//! implementation and the shared implementation for selected primitives; native
//! platform routes are interchangeable only when vectors and typed-error tests
//! prove identical input, output, failure, and edge-case behavior.
//!
//! ## Security posture
//!
//! `#![forbid(unsafe_code)]` here; secret material is returned in zeroizing
//! wrappers; signature verification fails closed; and cross-implementation
//! conformance vectors pin the Rust output against an independent oracle.
//! See `SECURITY.md` and `SECURITY_MEMORY_MODEL.md` at the repository root.
//!
//! Compile-checked usage examples live in the crate README so tests remain
//! separate from production implementation files.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

#[cfg(all(feature = "wasm", not(target_arch = "wasm32"), not(feature = "native")))]
compile_error!(
    "reallyme-crypto's `wasm` backend lane must be checked with \
     `--target wasm32-unknown-unknown`. Host builds should use the `native` \
     backend lane, or include `native` when running all-feature host checks."
);

pub use crypto_core as core;
pub use crypto_core::{
    AeadAlgorithm, Algorithm, CryptoError, HashAlgorithm, KeyWrapAlgorithm, MacAlgorithm,
};

mod aead_error;
#[cfg(any(
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024",
    feature = "x-wing"
))]
mod kem_error;
#[cfg(any(
    feature = "x25519",
    feature = "p256",
    feature = "p384",
    feature = "p521"
))]
mod key_agreement_error;
mod signature_error;

/// Operation-layer domain conventions shared by Rust and adapter boundaries.
pub mod operations;

/// Typed ownership, retention, export, and destruction contracts for secrets.
pub mod secret_material;

/// JSON Web Key envelope types and public-key conversion helpers.
#[cfg(feature = "jwk")]
pub use envelopes_jwk as jwk;

/// Bidirectional conversion between JWK and Multikey public-key envelopes.
#[cfg(feature = "jwk-multikey")]
pub use envelopes_jwk_multikey as jwk_multikey;

/// Algorithm-selected dispatch: keygen, sign/verify, key agreement, KEM, AEAD,
/// hashing, and multikey binding routed by an [`core::Algorithm`] selector.
#[cfg(feature = "dispatch")]
pub mod dispatch;

/// Primary generated protobuf operation-response boundary.
#[cfg(feature = "operation-response")]
pub mod operation_contract;

/// Signer/verifier traits and dispatch-backed implementations for producing and
/// checking detached signatures.
#[cfg(feature = "signer")]
pub mod signer {
    pub use crypto_signer::{
        DispatchSigner, DispatchVerifier, Signer, SignerError, SignerFailureKind, Verifier,
        VerifierError, VerifierFailureKind,
    };
}

/// AES-GCM authenticated encryption primitives and their typed key/nonce
/// wrappers and length constants.
#[cfg(feature = "aes")]
pub mod aes;

/// AES-256-GCM authenticated encryption with typed key and nonce boundaries.
#[cfg(feature = "aes")]
pub mod aes256_gcm;

/// AES-128, AES-192, and AES-256 Key Wrap (RFC 3394) for compact key material.
#[cfg(feature = "aes-kw")]
pub mod aes_kw;

/// AES-256-GCM-SIV nonce-misuse-resistant authenticated encryption primitive and
/// its typed key/nonce wrappers and length constants.
#[cfg(feature = "aes-gcm-siv")]
pub mod aes_gcm_siv;

/// ChaCha20-Poly1305 and XChaCha20-Poly1305 authenticated encryption
/// primitives with typed key and nonce wrappers.
#[cfg(feature = "chacha20-poly1305")]
pub mod chacha20_poly1305;

/// Argon2id password-based key derivation, including platform-tuned cost
/// profiles and typed salt/secret/derived-key wrappers.
#[cfg(feature = "argon2id")]
pub mod argon2id;

/// OS-backed cryptographically secure randomness and typed generators for AEAD
/// nonces and Argon2 salts.
#[cfg(feature = "csprng")]
pub mod csprng {
    pub use crypto_csprng::{
        generate_aead_nonce_12, generate_argon2_salt_16, generate_argon2_salt_32, generate_bytes,
        AeadNonce12, Argon2Salt16, Argon2Salt32, OsSecureRandom, RandomBytes, SecureRandom,
        AEAD_NONCE_12_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH,
    };
}

/// Ed25519 signatures: keypair generation, sign/verify, and public-key encoding.
#[cfg(feature = "ed25519")]
pub mod ed25519;

/// HMAC authentication tags over SHA-256, SHA-384, and SHA-512.
#[cfg(feature = "hmac")]
pub mod hmac;

/// JWA ECDH-ES Concat KDF over SHA-256 for deriving content-encryption keys
/// from an ECDH shared secret.
#[cfg(feature = "concat-kdf")]
pub mod concat_kdf;

/// NIST P-256 (secp256r1) ECDSA over pre-hashed messages, with public-key
/// compression and Secure Enclave handle encoding.
#[cfg(feature = "p256")]
pub mod p256;

/// NIST P-384 (secp384r1) ECDSA and ECDH, with public-key
/// compression/decompression helpers.
#[cfg(feature = "p384")]
pub mod p384;

/// NIST P-521 (secp521r1) ECDSA and ECDH, with public-key
/// compression/decompression helpers.
#[cfg(feature = "p521")]
pub mod p521;

/// PBKDF2 password-based key derivation conforming to RFC 8018.
#[cfg(feature = "pbkdf2")]
pub mod pbkdf2;

/// RSA signature verification for PKCS#1 v1.5 and PSS.
#[cfg(feature = "rsa")]
pub mod rsa;

/// secp256k1 ECDSA signs SHA-256(message) once, returns compact low-S `r || s`,
/// and uses compressed SEC1 public keys as the canonical API representation.
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

/// X25519 Diffie–Hellman key agreement and public-key encoding.
#[cfg(feature = "x25519")]
pub mod x25519;

/// X-Wing hybrid KEM over X25519 plus ML-KEM-768.
#[cfg(feature = "x-wing")]
pub mod x_wing;

/// RFC 9180 HPKE Base-mode encryption over supported DHKEM/HKDF/AEAD suites.
#[cfg(feature = "hpke-api")]
pub mod hpke;

/// HKDF (RFC 5869) extract-and-expand key derivation over the SHA-2/SHA-3 suites,
/// with domain-separated key derivation helpers.
#[cfg(feature = "hkdf")]
pub mod hkdf;

/// KMAC256 key derivation for protocols using NIST SP 800-108 and SP 800-185.
#[cfg(feature = "kmac")]
pub mod kmac;

/// ML-DSA-44 (FIPS 204) post-quantum signatures: keygen, sign/verify, and
/// public-key encoding.
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44;

/// ML-DSA-65 (FIPS 204) post-quantum signatures: keygen, sign/verify, and
/// public-key encoding.
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65;

/// ML-DSA-87 (FIPS 204) post-quantum signatures: keygen, sign/verify, and
/// public-key encoding.
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87;

/// SLH-DSA-SHA2-128s (FIPS 205) hash-based post-quantum signatures.
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

/// ML-KEM-512 (FIPS 203) post-quantum key encapsulation: keygen, encapsulate,
/// and decapsulate.
#[cfg(feature = "ml-kem-512")]
pub mod ml_kem_512;

/// ML-KEM-768 (FIPS 203) post-quantum key encapsulation: keygen, encapsulate,
/// and decapsulate.
#[cfg(feature = "ml-kem-768")]
pub mod ml_kem_768;

/// ML-KEM-1024 (FIPS 203) post-quantum key encapsulation: keygen, encapsulate,
/// and decapsulate.
#[cfg(feature = "ml-kem-1024")]
pub mod ml_kem_1024;

/// SHA-2-256 hashing and its fixed-length digest wrapper.
#[cfg(feature = "sha2")]
pub mod sha2;

/// SHA-3-256 hashing and its fixed-length digest wrapper.
#[cfg(feature = "sha3")]
pub mod sha3;
