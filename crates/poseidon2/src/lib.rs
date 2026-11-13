// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! BN254 Poseidon2 hashing with the byte encoding used by ReallyMe ZK circuits.
//!
//! The parameter set is fixed to width 4, rate 3, S-box exponent 5, 8 full
//! rounds, and 56 partial rounds. This API accepts bytes, maps each byte to one
//! field element, and places the byte count multiplied by 2^64 in the capacity
//! element. It always applies a final permutation, including for a full block.

#![forbid(unsafe_code)]

/// Protected protobuf inputs and existing native helper contracts.
#[cfg(feature = "proto")]
pub mod proto_helpers;

mod hash;

pub use hash::{hash_bytes, Poseidon2Digest, Poseidon2Error, MAX_INPUT_BYTES};
