// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for operating-system randomness requests.

use crypto_core::RngOutputKind;

use super::{OperationError, ProviderErrorReason};
use crate::secret_material::{
    bind_operation_policy, bind_random_fill_policy, SecretMaterialOperation,
};

/// Fills `output` with cryptographically secure random bytes.
pub fn fill_bytes(output: &mut [u8], kind: RngOutputKind) -> Result<(), OperationError> {
    let _policy = bind_random_fill_policy(kind);
    #[cfg(feature = "csprng")]
    {
        use crypto_csprng::{OsSecureRandom, SecureRandom};

        let mut rng = OsSecureRandom;
        rng.fill_secure(output, kind)
            .map_err(|_| randomness_unavailable())
    }

    #[cfg(not(feature = "csprng"))]
    {
        let _ = (output, kind);
        Err(unsupported_algorithm())
    }
}

/// Generates a 12-byte AEAD nonce.
#[cfg(feature = "csprng")]
pub fn generate_aead_nonce_12() -> Result<crypto_csprng::AeadNonce12, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::RandomNonce);
    let mut rng = crypto_csprng::OsSecureRandom;
    crypto_csprng::generate_aead_nonce_12(&mut rng).map_err(|_| randomness_unavailable())
}

/// Generates a 16-byte Argon2 salt.
#[cfg(feature = "csprng")]
pub fn generate_argon2_salt_16() -> Result<crypto_csprng::Argon2Salt16, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::RandomSalt);
    let mut rng = crypto_csprng::OsSecureRandom;
    crypto_csprng::generate_argon2_salt_16(&mut rng).map_err(|_| randomness_unavailable())
}

/// Generates a 32-byte Argon2 salt.
#[cfg(feature = "csprng")]
pub fn generate_argon2_salt_32() -> Result<crypto_csprng::Argon2Salt32, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::RandomSalt);
    let mut rng = crypto_csprng::OsSecureRandom;
    crypto_csprng::generate_argon2_salt_32(&mut rng).map_err(|_| randomness_unavailable())
}

fn randomness_unavailable() -> OperationError {
    OperationError::Provider {
        reason: ProviderErrorReason::RandomnessUnavailable,
    }
}

#[cfg(not(feature = "csprng"))]
fn unsupported_algorithm() -> OperationError {
    OperationError::Provider {
        reason: ProviderErrorReason::UnsupportedAlgorithm,
    }
}
