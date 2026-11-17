// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Sha3_256Digest, SHA3_256_DIGEST_LENGTH};
use crypto_proto::contract_constants::incremental_hash::SHA3_256_MAX_INPUT_BYTES;

/// Exclusively owned SHA3-256 context defined by the incremental protobuf contract.
///
/// No state export or clone is provided: partially absorbed input may be secret.
/// Finalization consumes this context; explicit zeroization invalidates it.
pub struct Sha3_256Hasher {
    state: Option<Sha3_256>,
    processed_bytes: u64,
}

impl Sha3_256Hasher {
    /// Start a fresh SHA3-256 transcript without allocating.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Some(Sha3_256::new()),
            processed_bytes: 0,
        }
    }

    /// Append exact bytes, rejecting overflow before changing the transcript.
    pub fn update(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        let state = self
            .state
            .as_mut()
            .ok_or(CryptoError::BACKEND_INVALID_STATE)?;
        let length =
            u64::try_from(input.len()).map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        let remaining = SHA3_256_MAX_INPUT_BYTES
            .checked_sub(self.processed_bytes)
            .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        if length > remaining {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        let next = self
            .processed_bytes
            .checked_add(length)
            .ok_or(CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        state.update(input);
        self.processed_bytes = next;
        Ok(())
    }

    /// Total bytes accepted by this context, excluding rejected chunks.
    #[must_use]
    pub fn processed_bytes(&self) -> u64 {
        self.processed_bytes
    }

    /// Consume this context and finalize directly into the cleanup-owned digest.
    pub fn finalize(mut self) -> Result<Sha3_256Digest, CryptoError> {
        let state = self
            .state
            .take()
            .ok_or(CryptoError::BACKEND_INVALID_STATE)?;
        let mut digest = Sha3_256Digest {
            bytes: [0; SHA3_256_DIGEST_LENGTH],
        };
        state.finalize_into((&mut digest.bytes).into());
        Ok(digest)
    }
}

impl Default for Sha3_256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for Sha3_256Hasher {
    fn zeroize(&mut self) {
        // Taking drops the backend, whose zeroize feature wipes both the sponge
        // state and cursor. No backend state or buffered input escapes this owner.
        self.state = None;
        self.processed_bytes.zeroize();
    }
}

impl Drop for Sha3_256Hasher {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Sha3_256Hasher {}

#[cfg(test)]
#[path = "incremental_tests.rs"]
mod tests;
