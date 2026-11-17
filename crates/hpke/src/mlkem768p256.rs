// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-width entropy adapter for the MLKEM768-P256 HPKE backend.

use hpke::kem::{MlKem768P256 as Backend, SharedSecret};
use hpke::rand_core::CryptoRng;
use hpke::Kem;
use zeroize::Zeroizing;

use crate::random::FixedRandomness;
use crate::validation::MLKEM768_P256_ENCAPSULATION_RANDOMNESS_LEN;

pub(crate) struct MlKem768P256;

impl Kem for MlKem768P256 {
    type PublicKey = <Backend as Kem>::PublicKey;
    type PrivateKey = <Backend as Kem>::PrivateKey;
    type EncappedKey = <Backend as Kem>::EncappedKey;
    type NSecret = <Backend as Kem>::NSecret;

    const KEM_ID: u16 = Backend::KEM_ID;

    fn sk_to_pk(secret_key: &Self::PrivateKey) -> Self::PublicKey {
        Backend::sk_to_pk(secret_key)
    }

    fn derive_keypair(input_key_material: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        Backend::derive_keypair(input_key_material)
    }

    fn decap(
        recipient_secret_key: &Self::PrivateKey,
        sender_public_key: Option<&Self::PublicKey>,
        encapsulated_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, hpke::HpkeError> {
        if sender_public_key.is_some() {
            return Err(hpke::HpkeError::DecapError);
        }
        Backend::decap(recipient_secret_key, None, encapsulated_key).map(rebind_shared_secret)
    }

    fn encap_with_rng(
        recipient_public_key: &Self::PublicKey,
        sender_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        if sender_keypair.is_some() {
            return Err(hpke::HpkeError::EncapError);
        }

        // The concrete hybrid specifies 32 ML-KEM bytes plus a 128-byte
        // P-256 seed (draft-irtf-cfrg-concrete-hybrid-kems-04, section 3.1.1).
        // The backend samples 32-byte scalars on demand. Reserve the complete
        // seed here so unused candidates do not alter the transport's entropy
        // contract, and bound rejection sampling to those four candidates.
        let mut randomness = Zeroizing::new([0_u8; MLKEM768_P256_ENCAPSULATION_RANDOMNESS_LEN]);
        csprng.fill_bytes(randomness.as_mut_slice());
        let mut bounded_rng = FixedRandomness::new(randomness.as_slice());
        let (shared_secret, encapsulated_key) =
            Backend::encap_with_rng(recipient_public_key, None, &mut bounded_rng)?;
        if bounded_rng.was_exhausted() {
            // FixedRandomness lets the backend leave its infallible sampling
            // loop after exhaustion. That synthetic candidate must never
            // produce a successful encapsulation.
            return Err(hpke::HpkeError::EncapError);
        }
        Ok((rebind_shared_secret(shared_secret), encapsulated_key))
    }
}

fn rebind_shared_secret(secret: SharedSecret<Backend>) -> SharedSecret<MlKem768P256> {
    let mut output = SharedSecret::<MlKem768P256>::default();
    output.0.copy_from_slice(&secret.0);
    // Both the backend owner and the returned owner wipe their bytes on drop.
    output
}
