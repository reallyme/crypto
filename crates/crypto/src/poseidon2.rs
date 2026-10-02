// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-parameter BN254 Poseidon2 byte hashing.

pub use crypto_poseidon2::{
    hash_bytes, Poseidon2Digest, Poseidon2Error, Poseidon2ErrorReason, MAX_INPUT_BYTES,
};
