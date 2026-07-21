// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! DHKEM(secp256k1, HKDF-SHA256) adapter for IANA KEM `0x0016`.

use crypto_secp256k1::{derive_secp256k1_shared_secret, Secp256k1SharedSecret};
use hkdf::HkdfExtract;
use hpke::hybrid_array::typenum::{U32, U65};
use hpke::kdf::HkdfSha256;
use k256::elliptic_curve::{ops::ReduceNonZero, sec1::ToSec1Point};
use k256::{FieldBytes, NonZeroScalar, PublicKey, SecretKey};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::dhkem::{DhGroup, DhKem};
use crate::{HPKE_SECP256K1_PRIVATE_KEY_LEN, HPKE_SECP256K1_PUBLIC_KEY_LEN};

const KEM_ID: u16 = 0x0016;
const VERSION_LABEL: &[u8] = b"HPKE-v1";
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x16";
const DERIVE_LABEL: &[u8] = b"dkp_prk";
const CANDIDATE_LABEL: &[u8] = b"candidate";
const PRIVATE_KEY_LEN_U16: [u8; 2] = [0, 32];
const SEC1_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

pub(crate) enum Secp256k1Group {}

pub(crate) type DhKemSecp256k1HkdfSha256 = DhKem<Secp256k1Group>;

impl DhGroup for Secp256k1Group {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
    type RawSharedSecret = Secp256k1SharedSecret;
    type PublicKeySize = U65;
    type PrivateKeySize = U32;
    type SecretSize = U32;
    type KemKdf = HkdfSha256;

    const KEM_ID: u16 = KEM_ID;
    const PUBLIC_KEY_LEN: usize = HPKE_SECP256K1_PUBLIC_KEY_LEN;
    const PRIVATE_KEY_LEN: usize = HPKE_SECP256K1_PRIVATE_KEY_LEN;

    fn derive_private_key(input_key_material: &[u8]) -> Self::PrivateKey {
        let mut extract = HkdfExtract::<Sha256>::new(Some(&[]));
        extract.input_ikm(VERSION_LABEL);
        extract.input_ikm(KEM_SUITE_ID);
        extract.input_ikm(DERIVE_LABEL);
        extract.input_ikm(input_key_material);
        let (mut prk, hkdf) = extract.finalize();

        let mut last_candidate = Zeroizing::new([0_u8; HPKE_SECP256K1_PRIVATE_KEY_LEN]);
        for counter in 0_u8..=u8::MAX {
            if hkdf
                .expand_multi_info(
                    &[
                        &PRIVATE_KEY_LEN_U16,
                        VERSION_LABEL,
                        KEM_SUITE_ID,
                        CANDIDATE_LABEL,
                        &[counter],
                    ],
                    last_candidate.as_mut_slice(),
                )
                .is_ok()
            {
                if let Ok(secret_key) = SecretKey::from_slice(last_candidate.as_slice()) {
                    prk.zeroize();
                    return secret_key;
                }
            }
            last_candidate.zeroize();
        }

        // RFC 9180 specifies aborting after 256 rejected candidates, but the
        // selected backend's `Kem` trait cannot report DeriveKeyPairError.
        // Reduce the final pseudorandom candidate into [1, order) rather than
        // inheriting the backend's production panic. Reaching this branch has
        // probability below 2^-8000; the registered derivation is unchanged
        // for every conforming execution.
        let candidate = Zeroizing::new(FieldBytes::from(*last_candidate));
        let fallback = NonZeroScalar::reduce_nonzero(&*candidate);
        prk.zeroize();
        SecretKey::from(fallback)
    }

    fn private_key_from_bytes(encoded: &[u8]) -> Result<Self::PrivateKey, hpke::HpkeError> {
        SecretKey::from_slice(encoded).map_err(|_| hpke::HpkeError::ValidationError)
    }

    fn write_private_key(private_key: &Self::PrivateKey, output: &mut [u8]) {
        output.copy_from_slice(&private_key.to_bytes());
    }

    fn public_key_from_bytes(encoded: &[u8]) -> Result<Self::PublicKey, hpke::HpkeError> {
        if encoded.first().copied() != Some(SEC1_UNCOMPRESSED_POINT_TAG) {
            return Err(hpke::HpkeError::ValidationError);
        }
        PublicKey::from_sec1_bytes(encoded).map_err(|_| hpke::HpkeError::ValidationError)
    }

    fn write_public_key(public_key: &Self::PublicKey, output: &mut [u8]) {
        output.copy_from_slice(public_key.as_affine().to_sec1_point(false).as_bytes());
    }

    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey {
        private_key.public_key()
    }

    fn private_keys_equal(left: &Self::PrivateKey, right: &Self::PrivateKey) -> Choice {
        left.ct_eq(right)
    }

    fn diffie_hellman(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::RawSharedSecret, hpke::HpkeError> {
        let encoded_public_key = public_key.as_affine().to_sec1_point(false);
        derive_secp256k1_shared_secret(
            private_key.to_bytes().as_slice(),
            encoded_public_key.as_bytes(),
        )
        .map_err(|_| hpke::HpkeError::EncapError)
    }

    fn shared_secret_bytes(secret: &Self::RawSharedSecret) -> &[u8] {
        secret.as_bytes()
    }
}
