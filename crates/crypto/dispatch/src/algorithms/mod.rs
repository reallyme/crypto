// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// AES-256-GCM AEAD adapter.
pub mod aes256_gcm;
/// AES-256-GCM-SIV AEAD adapter.
pub mod aes256_gcm_siv;
/// ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD adapters.
pub mod chacha20_poly1305;
/// Ed25519 signature adapter.
pub mod ed25519;
/// HMAC-SHA-256 and HMAC-SHA-512 adapters.
pub mod hmac;
mod keypair_result;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
mod map_signature_error;
/// ML-DSA-44 signature adapter.
pub mod ml_dsa_44;
/// ML-DSA-65 signature adapter.
pub mod ml_dsa_65;
/// ML-DSA-87 signature adapter.
pub mod ml_dsa_87;
/// ML-KEM-1024 key encapsulation adapter.
pub mod ml_kem_1024;
/// ML-KEM-512 key encapsulation adapter.
pub mod ml_kem_512;
/// ML-KEM-768 key encapsulation adapter.
pub mod ml_kem_768;
/// NIST P-256 (secp256r1) signature adapter.
pub mod p256;
/// NIST P-384 (secp384r1) signature adapter.
pub mod p384;
/// NIST P-521 (secp521r1) signature adapter.
pub mod p521;
/// secp256k1 signature adapter.
pub mod secp256k1;
/// SHA-384 and SHA-512 (SHA-2) hash adapters.
pub mod sha2;
/// SHA-256 (SHA-2) hash adapter.
pub mod sha2_256;
/// SHA3-224, SHA3-384, and SHA3-512 hash adapters.
pub mod sha3;
/// SHA3-256 hash adapter.
pub mod sha3_256;
/// X25519 Diffie–Hellman adapter.
pub mod x25519;
/// X-Wing hybrid KEM adapters.
pub mod x_wing;

#[allow(unused_imports)]
pub(crate) use keypair_result::KeypairResultExt;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
pub(crate) use map_signature_error::map_verify_error;
