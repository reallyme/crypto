// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KeyAgreementFailureKind};
use zeroize::Zeroizing;

use crate::{X448PrivateKey, X448PublicKey, X448_PRIVATE_KEY_LEN};

/// Generates an X448 keypair with operating-system randomness.
pub fn generate_x448_keypair() -> Result<(X448PrivateKey, X448PublicKey), CryptoError> {
    let mut seed = Zeroizing::new([0_u8; X448_PRIVATE_KEY_LEN]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| CryptoError::KeyAgreementFailure {
        kind: KeyAgreementFailureKind::KeyGenerationFailed,
    })?;
    generate_x448_keypair_from_seed(&seed)
}

/// Deterministically derives an X448 keypair from a caller-owned 56-byte seed.
pub fn generate_x448_keypair_from_seed(
    seed: &[u8; X448_PRIVATE_KEY_LEN],
) -> Result<(X448PrivateKey, X448PublicKey), CryptoError> {
    let private_key = X448PrivateKey::from_bytes(seed)?;
    let public_key = X448PublicKey::from(&private_key);
    Ok((private_key, public_key))
}
