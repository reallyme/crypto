// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use taceo_poseidon2::bn254::t4::permutation_in_place;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Largest byte preimage supported by the reviewed ReallyMe ZK circuits.
pub const MAX_INPUT_BYTES: usize = 515;
const RATE: usize = 3;
const WIDTH: usize = 4;
const DIGEST_BYTES: usize = 32;
const LIMB_BYTES: usize = core::mem::size_of::<u64>();
const LENGTH_DOMAIN_SHIFT: u32 = 64;

/// A canonical, big-endian BN254 field element returned by Poseidon2.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Poseidon2Digest {
    bytes: [u8; DIGEST_BYTES],
}

impl Poseidon2Digest {
    /// Borrow the canonical field-element encoding.
    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.bytes
    }

    /// Transfer the digest bytes to the caller.
    pub fn into_bytes(mut self) -> [u8; DIGEST_BYTES] {
        core::mem::take(&mut self.bytes)
    }
}

/// Stable reasons for rejecting a Poseidon2 input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum Poseidon2ErrorReason {
    /// The circuit's reviewed input bound was exceeded.
    #[error("Poseidon2 input exceeds the supported bound")]
    InputTooLong,
    /// The input length could not be represented in the sponge domain tag.
    #[error("Poseidon2 input length cannot be represented")]
    InvalidLength,
}

/// A typed Poseidon2 hashing failure without input or output bytes.
#[derive(Debug, Error)]
#[error("{reason}")]
pub struct Poseidon2Error {
    reason: Poseidon2ErrorReason,
}

impl Poseidon2Error {
    /// Return a stable, data-free failure reason.
    pub fn reason(&self) -> Poseidon2ErrorReason {
        self.reason
    }
}

/// Hash a byte preimage exactly as `poseidon2_bounded` does in ReallyMe ZK.
///
/// The mapping is one byte per BN254 field element. The input length is part
/// of the sponge domain and the 32-byte result is a canonical big-endian field
/// encoding. Input is borrowed so the caller retains ownership and can zeroize
/// sensitive preimages at its own boundary.
pub fn hash_bytes(input: &[u8]) -> Result<Poseidon2Digest, Poseidon2Error> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(Poseidon2Error {
            reason: Poseidon2ErrorReason::InputTooLong,
        });
    }
    let input_length = u64::try_from(input.len()).map_err(|_| Poseidon2Error {
        reason: Poseidon2ErrorReason::InvalidLength,
    })?;
    let capacity = Fr::from(input_length) * Fr::from(1_u128 << LENGTH_DOMAIN_SHIFT);
    let mut state = Zeroizing::new([Fr::zero(); WIDTH]);
    state[RATE] = capacity;
    let mut cache = Zeroizing::new([Fr::zero(); RATE]);
    let mut cache_length = 0_usize;

    for byte in input {
        if cache_length == RATE {
            absorb_block(&mut state, &cache, cache_length);
            cache.zeroize();
            cache_length = 0;
        }
        let cache_slot = cache.get_mut(cache_length).ok_or(Poseidon2Error {
            reason: Poseidon2ErrorReason::InvalidLength,
        })?;
        *cache_slot = Fr::from(*byte);
        cache_length = cache_length.checked_add(1).ok_or(Poseidon2Error {
            reason: Poseidon2ErrorReason::InvalidLength,
        })?;
    }
    // Noir's sponge always performs this final duplex, even after a full
    // block and for the empty preimage. Both cases affect cross-lane parity.
    absorb_block(&mut state, &cache, cache_length);

    let mut limbs = Zeroizing::new(state[0].into_bigint().0);
    let mut bytes = [0_u8; DIGEST_BYTES];
    for (chunk, limb) in bytes
        .as_chunks_mut::<LIMB_BYTES>()
        .0
        .iter_mut()
        .zip(limbs.iter().rev())
    {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    limbs.zeroize();
    Ok(Poseidon2Digest { bytes })
}

fn absorb_block(state: &mut [Fr; WIDTH], cache: &[Fr; RATE], cache_length: usize) {
    for (state_element, cache_element) in state.iter_mut().zip(cache.iter()).take(cache_length) {
        *state_element += *cache_element;
    }
    permutation_in_place(state);
}
