// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Ed25519 signature adapter.
#[cfg(feature = "ed25519")]
pub mod ed25519;
mod keypair_result;
/// ML-DSA-44 signature adapter.
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44;
/// ML-DSA-65 signature adapter.
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65;
/// ML-DSA-87 signature adapter.
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87;
/// ML-KEM-1024 key encapsulation adapter.
#[cfg(feature = "ml-kem-1024")]
pub mod ml_kem_1024;
/// ML-KEM-512 key encapsulation adapter.
#[cfg(feature = "ml-kem-512")]
pub mod ml_kem_512;
/// ML-KEM-768 key encapsulation adapter.
#[cfg(feature = "ml-kem-768")]
pub mod ml_kem_768;
/// NIST P-256 (secp256r1) signature adapter.
#[cfg(feature = "p256")]
pub mod p256;
/// NIST P-384 (secp384r1) signature adapter.
#[cfg(feature = "p384")]
pub mod p384;
/// NIST P-521 (secp521r1) signature adapter.
#[cfg(feature = "p521")]
pub mod p521;
/// secp256k1 signature adapter.
#[cfg(feature = "secp256k1")]
pub mod secp256k1;
/// X25519 Diffie–Hellman adapter.
#[cfg(feature = "x25519")]
pub mod x25519;
/// X-Wing hybrid KEM adapters.
#[cfg(feature = "x-wing")]
pub mod x_wing;

#[allow(unused_imports)]
pub(crate) use keypair_result::KeypairResultExt;
