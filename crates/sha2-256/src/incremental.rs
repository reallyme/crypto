// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha2::{
    block_api::{compress256, Sha256VarCore},
    digest::{array::Array, block_api::Buffer},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, Sha2_256Digest, SHA2_256_DIGEST_LENGTH};
use crypto_proto::contract_constants::incremental_hash::SHA2_256_MAX_INPUT_BYTES;

const BYTE_BITS: u64 = 8;

/// Exclusively owned SHA-256 context defined by the incremental protobuf contract.
///
/// Compression and padding remain the upstream implementation used by the
/// one-shot operation. State and buffered input retain zeroizing owners.
pub struct Sha2_256Hasher {
    state: Zeroizing<[u32; 8]>,
    buffer: Zeroizing<Buffer<Sha256VarCore>>,
    processed_bytes: u64,
    active: bool,
}

impl Sha2_256Hasher {
    /// Start a fresh SHA-256 transcript without allocating.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Zeroizing::new(crate::hash_message::INITIAL_STATE),
            buffer: Zeroizing::new(Buffer::<Sha256VarCore>::default()),
            processed_bytes: 0,
            active: true,
        }
    }

    /// Append exact bytes, rejecting overflow before changing the transcript.
    pub fn update(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        if !self.active {
            return Err(CryptoError::BACKEND_INVALID_STATE);
        }
        let length =
            u64::try_from(input.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let next = self
            .processed_bytes
            .checked_add(length)
            .filter(|total| *total <= SHA2_256_MAX_INPUT_BYTES)
            .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        self.buffer.digest_blocks(input, |blocks| {
            compress256(&mut self.state, Array::cast_slice_to_core(blocks));
        });
        self.processed_bytes = next;
        Ok(())
    }

    /// Total bytes accepted by this context, excluding rejected chunks.
    #[must_use]
    pub fn processed_bytes(&self) -> u64 {
        self.processed_bytes
    }

    /// Consume this context and finalize directly into the cleanup-owned digest.
    pub fn finalize(mut self) -> Result<Sha2_256Digest, CryptoError> {
        if !self.active {
            return Err(CryptoError::BACKEND_INVALID_STATE);
        }
        let bits = self
            .processed_bytes
            .checked_mul(BYTE_BITS)
            .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        self.buffer.len64_padding_be(bits, |block| {
            compress256(&mut self.state, core::slice::from_ref(&block.0));
        });
        let mut digest = Sha2_256Digest {
            bytes: [0; SHA2_256_DIGEST_LENGTH],
        };
        for (destination, word) in digest
            .bytes
            .as_chunks_mut::<{ size_of::<u32>() }>()
            .0
            .iter_mut()
            .zip(self.state.iter())
        {
            let encoded = Zeroizing::new(word.to_be_bytes());
            destination.copy_from_slice(encoded.as_ref());
        }
        Ok(digest)
    }
}

impl Default for Sha2_256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for Sha2_256Hasher {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.processed_bytes.zeroize();
        self.active = false;
    }
}

impl Drop for Sha2_256Hasher {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Sha2_256Hasher {}

#[cfg(test)]
#[path = "incremental_tests.rs"]
mod tests;
