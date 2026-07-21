// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use hpke::kem::{
    DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, MlKem1024, MlKem1024P384, MlKem768,
    MlKem768P256, X25519HkdfSha256, XWing,
};
use hpke::{Kem as HpkeKem, Serializable};
use zeroize::{Zeroize, Zeroizing};

use crate::error::HpkeError;
use crate::identifiers::{HpkeKemId, HpkeSuite};
use crate::mlkem512::MlKem512;
use crate::secp256k1::DhKemSecp256k1HkdfSha256;
use crate::types::{HpkeKeyPair, HpkePrivateKeyBytes};
use crate::validation::{kem_parameters, require_executable_suite};
use crate::x448::DhKemX448HkdfSha512;

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

    match suite.kem {
        HpkeKemId::DhKemP256HkdfSha256 => {
            derive_keypair_for::<DhP256HkdfSha256>(suite, input_key_material)
        }
        HpkeKemId::DhKemP384HkdfSha384 => {
            derive_keypair_for::<DhP384HkdfSha384>(suite, input_key_material)
        }
        HpkeKemId::DhKemP521HkdfSha512 => {
            derive_keypair_for::<DhP521HkdfSha512>(suite, input_key_material)
        }
        HpkeKemId::DhKemSecp256k1HkdfSha256 => {
            derive_keypair_for::<DhKemSecp256k1HkdfSha256>(suite, input_key_material)
        }
        HpkeKemId::DhKemX25519HkdfSha256 => {
            derive_keypair_for::<X25519HkdfSha256>(suite, input_key_material)
        }
        HpkeKemId::DhKemX448HkdfSha512 => {
            derive_keypair_for::<DhKemX448HkdfSha512>(suite, input_key_material)
        }
        HpkeKemId::MlKem512 => derive_keypair_for::<MlKem512>(suite, input_key_material),
        HpkeKemId::MlKem768 => derive_keypair_for::<MlKem768>(suite, input_key_material),
        HpkeKemId::MlKem1024 => derive_keypair_for::<MlKem1024>(suite, input_key_material),
        HpkeKemId::MlKem768P256 => derive_keypair_for::<MlKem768P256>(suite, input_key_material),
        HpkeKemId::MlKem1024P384 => derive_keypair_for::<MlKem1024P384>(suite, input_key_material),
        HpkeKemId::XWing => derive_keypair_for::<XWing>(suite, input_key_material),
        HpkeKemId::DhKemCp256HkdfSha256
        | HpkeKemId::DhKemCp384HkdfSha384
        | HpkeKemId::DhKemCp521HkdfSha512
        | HpkeKemId::DhKemX25519ElligatorHkdfSha256
        | HpkeKemId::X25519Kyber768Draft00 => Err(HpkeError::UnsupportedKem),
    }
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
