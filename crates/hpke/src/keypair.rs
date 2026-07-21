// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::{Kem as HpkeKem, Serializable};
use zeroize::{Zeroize, Zeroizing};

use crate::error::HpkeError;
use crate::identifiers::HpkeSuite;
use crate::types::{HpkeKeyPair, HpkePrivateKeyBytes};
use crate::validation::{kem_parameters, require_executable_suite};

/// Generates a fresh HPKE KEM keypair using operating-system randomness.
pub fn keygen(suite: HpkeSuite) -> Result<HpkeKeyPair, HpkeError> {
    require_executable_suite(suite)?;
    let input_length = kem_parameters(suite.kem)?.private_key_len;
    let mut input_key_material = Zeroizing::new(vec![0_u8; input_length]);
    getrandom::fill(input_key_material.as_mut_slice())
        .map_err(|_| HpkeError::RandomnessUnavailable)?;
    derive_keypair(suite, input_key_material.as_slice())
}

/// Deterministically derives an HPKE KEM keypair from suite-sized input keying
/// material.
pub fn derive_keypair(
    suite: HpkeSuite,
    input_key_material: &[u8],
) -> Result<HpkeKeyPair, HpkeError> {
    require_executable_suite(suite)?;
    if input_key_material.len() != kem_parameters(suite.kem)?.private_key_len {
        return Err(HpkeError::InvalidInputKeyMaterial);
    }

    derive_keypair_from_ikm(suite, input_key_material)
}

/// Deterministically derives an HPKE KEM keypair from arbitrary-length input
/// keying material.
///
/// Each KEM applies its registered HPKE `DeriveKeyPair` procedure to the caller
/// input, including any KEM-specific draft normalization. This is the
/// OpenMLS-friendly entry point for MLS secrets whose length does not match the
/// KEM's serialized private-key length.
pub fn derive_keypair_from_ikm(
    suite: HpkeSuite,
    input_key_material: &[u8],
) -> Result<HpkeKeyPair, HpkeError> {
    require_executable_suite(suite)?;
    if input_key_material.is_empty() {
        return Err(HpkeError::InvalidInputKeyMaterial);
    }

    dispatch_kem!(suite.kem, derive_keypair_for, suite, input_key_material)
}

fn derive_keypair_for<Kem>(
    suite: HpkeSuite,
    input_key_material: &[u8],
) -> Result<HpkeKeyPair, HpkeError>
where
    Kem: HpkeKem,
{
    let (private_key, public_key) = Kem::derive_keypair(input_key_material);
    let public_key = public_key.to_bytes().as_slice().to_vec();
    let mut serialized_private_key = private_key.to_bytes();
    let private_key = HpkePrivateKeyBytes::new(serialized_private_key.as_slice().to_vec());
    serialized_private_key.as_mut_slice().zeroize();

    let parameters = kem_parameters(suite.kem)?;
    if public_key.len() != parameters.public_key_len
        || private_key.as_slice().len() != parameters.private_key_len
    {
        return Err(HpkeError::KeyGenerationFailed);
    }

    Ok(HpkeKeyPair::new(public_key, private_key))
}
