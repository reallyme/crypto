// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JSON Web Key encoders for ReallyMe public key material.

//! The crate intentionally treats JWK as serialization over validated public
//! bytes. Classical curves follow JOSE conventions. Post-quantum public keys
//! use ReallyMe's draft-aligned `AKP` wire-format choice pinned by conformance
//! vectors so they do not overload RFC 8037 `OKP` curves.

/// JWK data structures and serialization options.
pub mod jwk;

pub mod ed25519;
pub mod mldsa87;
pub mod mlkem1024;
pub mod p256;
pub mod pq;
pub mod secp256k1;
pub mod x25519;

pub use jwk::{public_key_bytes_from_jwk, AkpJwk, EcJwk, Jwk, JwkOptions, Jwks, OkpJwk};

pub use ed25519::{ed25519_public_key_to_jwk, ed25519_public_key_to_jwk_jcs};
pub use mldsa87::{mldsa87_public_key_to_jwk, mldsa87_public_key_to_jwk_jcs};
pub use mlkem1024::{mlkem1024_public_key_to_jwk, mlkem1024_public_key_to_jwk_jcs};
pub use p256::{p256_public_key_to_jwk, p256_public_key_to_jwk_jcs};
pub use pq::{
    mldsa44_public_key_to_jwk, mldsa44_public_key_to_jwk_jcs, mldsa65_public_key_to_jwk,
    mldsa65_public_key_to_jwk_jcs, mlkem512_public_key_to_jwk, mlkem512_public_key_to_jwk_jcs,
    mlkem768_public_key_to_jwk, mlkem768_public_key_to_jwk_jcs,
    slh_dsa_sha2_128s_public_key_to_jwk, slh_dsa_sha2_128s_public_key_to_jwk_jcs,
    x_wing_768_public_key_to_jwk, x_wing_768_public_key_to_jwk_jcs,
};
pub use secp256k1::{secp256k1_public_key_to_jwk, secp256k1_public_key_to_jwk_jcs};
pub use x25519::{x25519_public_key_to_jwk, x25519_public_key_to_jwk_jcs};

pub mod error;
pub use error::JwtError;
