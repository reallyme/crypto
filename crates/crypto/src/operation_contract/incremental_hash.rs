// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stateful generated-contract adapter for local incremental hashing.
//!
//! The context belongs to its caller. It has no serialized state or global
//! handle table; generated messages describe its inputs and result exactly.

use buffa::{EnumValue, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoHashResult, CryptoIncrementalHashFinalizeRequest, CryptoIncrementalHashStartRequest,
    CryptoIncrementalHashUpdateRequest, CryptoIncrementalHashUpdateResult, HashAlgorithm,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Caller-owned context for the schema-defined start/update/finalize lifecycle.
pub struct IncrementalHash {
    state: State,
}

enum State {
    #[cfg(feature = "sha2")]
    Sha2(crate::sha2::Sha2_256Hasher),
    #[cfg(feature = "sha3")]
    Sha3(crate::sha3::Sha3_256Hasher),
}

impl IncrementalHash {
    /// Start an enabled algorithm.
    ///
    /// Unspecified, unknown, and unavailable selectors return
    /// `PROVIDER_UNSUPPORTED_ALGORITHM`, matching one-shot hashing.
    pub fn start(request: &CryptoIncrementalHashStartRequest) -> Result<Self, CryptoError> {
        let state = match request.algorithm.as_known() {
            #[cfg(feature = "sha2")]
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_256) => {
                State::Sha2(crate::sha2::Sha2_256Hasher::new())
            }
            #[cfg(feature = "sha3")]
            Some(HashAlgorithm::HASH_ALGORITHM_SHA3_256) => {
                State::Sha3(crate::sha3::Sha3_256Hasher::new())
            }
            _ => return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
        };
        Ok(Self { state })
    }

    /// Append the generated request's exact guarded input bytes.
    pub fn update(
        &mut self,
        request: &CryptoIncrementalHashUpdateRequest,
    ) -> Result<CryptoIncrementalHashUpdateResult, CryptoError> {
        let processed_bytes = match &mut self.state {
            #[cfg(feature = "sha2")]
            State::Sha2(state) => {
                state.update(request.input.as_slice())?;
                state.processed_bytes()
            }
            #[cfg(feature = "sha3")]
            State::Sha3(state) => {
                state.update(request.input.as_slice())?;
                state.processed_bytes()
            }
        };
        Ok(CryptoIncrementalHashUpdateResult { processed_bytes })
    }

    /// Consume the context and return the established generated hash result.
    pub fn finalize(
        self,
        _request: &CryptoIncrementalHashFinalizeRequest,
    ) -> Result<CryptoHashResult, CryptoError> {
        let (algorithm, digest) = match self.state {
            #[cfg(feature = "sha2")]
            State::Sha2(state) => (
                HashAlgorithm::HASH_ALGORITHM_SHA2_256,
                crypto_proto::SecretBytes::try_from_slice(state.finalize()?.as_bytes())?,
            ),
            #[cfg(feature = "sha3")]
            State::Sha3(state) => (
                HashAlgorithm::HASH_ALGORITHM_SHA3_256,
                crypto_proto::SecretBytes::try_from_slice(state.finalize()?.as_bytes())?,
            ),
        };
        Ok(CryptoHashResult {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(Algorithm::Hash(EnumValue::from(algorithm))),
            }),
            digest,
        })
    }
}

impl Zeroize for IncrementalHash {
    fn zeroize(&mut self) {
        match &mut self.state {
            #[cfg(feature = "sha2")]
            State::Sha2(state) => state.zeroize(),
            #[cfg(feature = "sha3")]
            State::Sha3(state) => state.zeroize(),
        }
    }
}
// Every state variant owns a leaf context with a zeroizing destructor.
impl ZeroizeOnDrop for IncrementalHash {}
