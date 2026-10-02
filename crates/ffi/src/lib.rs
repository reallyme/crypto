// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native C ABI surface for the audited cryptographic primitives.
//!
//! # Panic safety
//!
//! Unwinding across an `extern "C"` boundary is undefined behavior. Every
//! exported `extern "C"` function in this crate routes its body through
//! [`guard::ffi_guard`], which runs the body inside `std::panic::catch_unwind`
//! and converts any escaping panic into the [`status::CRYPTO_INTERNAL_ERROR`]
//! status code. Shipped native artifacts use the workspace's `release-ffi`
//! profile. Compilation fails unconditionally if the selected panic strategy
//! is not unwind-capable, so an artifact without an effective firewall cannot
//! be produced accidentally.

#![doc = include_str!("../README.md")]
// This crate is a native/mobile C ABI (staticlib/cdylib). It is meaningless
// on `wasm32`, where browsers consume the primitives through wasm-bindgen
// directly rather than a C ABI. Compiling it away on wasm32 also avoids a
// Cargo feature-unification hazard: a workspace-wide build with `--features
// wasm` on a wasm32 target would otherwise pull the primitives' wasm lane
// (whose return types differ) into this native-only surface.
#![cfg(not(target_arch = "wasm32"))]
#![deny(unsafe_code)]
// Foreign pointer access and fixed export names are permitted only in the
// boundary modules below. Shared validation lives in `pointer` and JNI guards.
// The public FFI safety contract is maintained in `abi/reallyme_crypto_ffi.h`
// so C, Swift, Kotlin, and Rust consumers read the same pointer/length rules.
#![allow(clippy::missing_safety_doc)]

#[cfg(not(panic = "unwind"))]
compile_error!(
    "crypto-ffi release artifacts require an unwind-capable panic strategy; use --profile release-ffi"
);

/// C ABI surface for AES-256-GCM authenticated encryption.
#[allow(unsafe_code)]
pub mod aes256_gcm;
/// C ABI surface for AES-256-GCM-SIV authenticated encryption.
#[allow(unsafe_code)]
pub mod aes256_gcm_siv;
/// C ABI surface for AES-128/192/256-KW key wrapping.
#[allow(unsafe_code)]
pub mod aes_kw;
/// C ABI surface for Argon2id password-based key derivation.
#[allow(unsafe_code)]
pub mod argon2id;
/// C ABI surface for BIP-340 Schnorr signing and x-only public-key encoding.
#[allow(unsafe_code)]
pub mod bip340_schnorr;
/// C ABI surface for ChaCha20-Poly1305 and XChaCha20-Poly1305.
#[allow(unsafe_code)]
pub mod chacha20_poly1305;
/// C ABI surface for constant-time byte-slice comparison.
#[allow(unsafe_code)]
pub mod constant_time;
/// C ABI surface for the operating-system CSPRNG helpers.
#[allow(unsafe_code)]
pub mod csprng;
/// C ABI surface for Ed25519 signing, verification, and key encoding.
#[allow(unsafe_code)]
pub mod ed25519;
pub mod guard;
/// C ABI surface for HKDF key derivation (SHA-256 / SHA3-256 suites).
#[allow(unsafe_code)]
pub mod hkdf;
/// C ABI surface for HMAC authentication (SHA-256 / SHA-512 suites).
#[allow(unsafe_code)]
pub mod hmac;
/// C ABI surface for HPKE Base-mode encryption.
#[allow(unsafe_code)]
pub mod hpke;
mod kem_status;
mod key_agreement_status;
/// C ABI surface for KMAC256 key derivation.
#[allow(unsafe_code)]
pub mod kmac;
/// JNI bridge used by the Kotlin package for Rust-only AEAD providers.
#[allow(unsafe_code)]
pub mod kotlin_aead;
/// JNI bridge used by the Kotlin package for Rust-only primitives.
#[allow(unsafe_code)]
pub mod kotlin_argon2id;
/// JNI bridge used by the Kotlin package for Rust-only KMAC derivation.
#[allow(unsafe_code)]
pub mod kotlin_kmac;
/// JNI bridge for the Kotlin protobuf process lane.
#[allow(unsafe_code)]
pub mod kotlin_proto;
/// Shared typed JNI result envelope for Kotlin native providers.
pub mod kotlin_result;
/// C ABI surface for ML-DSA-44 (post-quantum) signing and verification.
#[allow(unsafe_code)]
pub mod ml_dsa_44;
/// C ABI surface for ML-DSA-65 (post-quantum) signing and verification.
#[allow(unsafe_code)]
pub mod ml_dsa_65;
/// C ABI surface for ML-DSA-87 (post-quantum) signing and verification.
#[allow(unsafe_code)]
pub mod ml_dsa_87;
/// C ABI surface for ML-KEM-1024 (post-quantum) key encapsulation.
#[allow(unsafe_code)]
pub mod ml_kem_1024;
/// C ABI surface for ML-KEM-512 (post-quantum) key encapsulation.
#[allow(unsafe_code)]
pub mod ml_kem_512;
/// C ABI surface for ML-KEM-768 (post-quantum) key encapsulation.
#[allow(unsafe_code)]
pub mod ml_kem_768;
/// Generated operation-response C ABI entrypoint.
#[allow(unsafe_code)]
pub mod operation_response;
/// C ABI surface for NIST P-256 signing, verification, and key encoding.
#[allow(unsafe_code)]
pub mod p256;
/// C ABI surface for NIST P-384 signing, verification, and key encoding.
#[allow(unsafe_code)]
pub mod p384;
/// C ABI surface for NIST P-521 signing, verification, and key encoding.
#[allow(unsafe_code)]
pub mod p521;
/// C ABI surface for PBKDF2-HMAC-SHA-256/SHA-512 derivation.
#[allow(unsafe_code)]
pub mod pbkdf2;
/// Internal raw-pointer/length validation and buffer-write helpers.
#[allow(unsafe_code)]
pub mod pointer;
/// C ABI surface for RSA signature verification.
#[allow(unsafe_code)]
pub mod rsa;
/// C ABI surface for secp256k1 signing, verification, and key encoding.
#[allow(unsafe_code)]
pub mod secp256k1;
/// C ABI surface for the SHA-384 and SHA-512 digests.
#[allow(unsafe_code)]
pub mod sha2;
/// C ABI surface for the SHA-256 digest.
#[allow(unsafe_code)]
pub mod sha2_256;
/// C ABI surface for SHA3-224, SHA3-384, and SHA3-512 digests.
#[allow(unsafe_code)]
pub mod sha3;
/// C ABI surface for the SHA3-256 digest.
#[allow(unsafe_code)]
pub mod sha3_256;
mod signature_status;
/// C ABI surface for SLH-DSA-SHA2-128s (FIPS 205) signing and verification.
#[allow(unsafe_code)]
pub mod slh_dsa;
/// Status codes and shared result types for the C ABI surface.
pub mod status;
/// C ABI surface for X25519 Diffie-Hellman and key encoding.
#[allow(unsafe_code)]
pub mod x25519;
/// C ABI surface for X-Wing hybrid KEM suites.
#[allow(unsafe_code)]
pub mod x_wing;
