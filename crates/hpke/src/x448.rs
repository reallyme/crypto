// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! DHKEM(X448, HKDF-SHA512) adapter for RFC 9180 KEM `0x0021`.

use crypto_x448::{
    derive_x448_shared_secret, X448PrivateKey, X448PublicKey, X448SharedSecret,
    X448_PRIVATE_KEY_LEN, X448_PUBLIC_KEY_LEN,
};
use hkdf::HkdfExtract;
use hpke::hybrid_array::typenum::{U56, U64};
use hpke::kdf::HkdfSha512;
use sha2::Sha512;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::dhkem::{DhGroup, DhKem};

const KEM_ID: u16 = 0x0021;
const VERSION_LABEL: &[u8] = b"HPKE-v1";
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x21";
const DERIVE_LABEL: &[u8] = b"dkp_prk";
const PRIVATE_KEY_LABEL: &[u8] = b"sk";
const PRIVATE_KEY_LEN_U16: [u8; 2] = [0, 56];

pub(crate) enum X448Group {}

pub(crate) type DhKemX448HkdfSha512 = DhKem<X448Group>;

impl DhGroup for X448Group {
    type PrivateKey = Zeroizing<[u8; X448_PRIVATE_KEY_LEN]>;
    type PublicKey = X448PublicKey;
    type RawSharedSecret = X448SharedSecret;
    type PublicKeySize = U56;
    type PrivateKeySize = U56;
    type SecretSize = U64;
    type KemKdf = HkdfSha512;

    const KEM_ID: u16 = KEM_ID;
    const PUBLIC_KEY_LEN: usize = X448_PUBLIC_KEY_LEN;
    const PRIVATE_KEY_LEN: usize = X448_PRIVATE_KEY_LEN;

    fn derive_private_key(input_key_material: &[u8]) -> Self::PrivateKey {
        let mut extract = HkdfExtract::<Sha512>::new(Some(&[]));
        extract.input_ikm(VERSION_LABEL);
        extract.input_ikm(KEM_SUITE_ID);
        extract.input_ikm(DERIVE_LABEL);
        extract.input_ikm(input_key_material);
        let (mut prk, hkdf) = extract.finalize();

        let mut private_key = [0_u8; X448_PRIVATE_KEY_LEN];
        let expanded = hkdf.expand_multi_info(
            &[
                &PRIVATE_KEY_LEN_U16,
                VERSION_LABEL,
                KEM_SUITE_ID,
                PRIVATE_KEY_LABEL,
                &[],
            ],
            &mut private_key,
        );
        prk.zeroize();
        if expanded.is_err() {
            private_key.zeroize();
        }
        let normalized = X448PrivateKey::from_array(private_key);
        private_key.copy_from_slice(normalized.as_bytes());
        Zeroizing::new(private_key)
    }

    fn private_key_from_bytes(encoded: &[u8]) -> Result<Self::PrivateKey, hpke::HpkeError> {
        let bytes = <[u8; X448_PRIVATE_KEY_LEN]>::try_from(encoded)
            .map_err(|_| hpke::HpkeError::ValidationError)?;
        let normalized = X448PrivateKey::from_array(bytes);
        Ok(Zeroizing::new(*normalized.as_bytes()))
    }

    fn write_private_key(private_key: &Self::PrivateKey, output: &mut [u8]) {
        output.copy_from_slice(private_key.as_slice());
    }

    fn public_key_from_bytes(encoded: &[u8]) -> Result<Self::PublicKey, hpke::HpkeError> {
        X448PublicKey::from_bytes(encoded).map_err(|_| hpke::HpkeError::ValidationError)
    }

    fn write_public_key(public_key: &Self::PublicKey, output: &mut [u8]) {
        output.copy_from_slice(public_key.as_bytes());
    }

    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey {
        let private_key = X448PrivateKey::from_array(**private_key);
        X448PublicKey::from(&private_key)
    }

    fn private_keys_equal(left: &Self::PrivateKey, right: &Self::PrivateKey) -> Choice {
        left.as_slice().ct_eq(right.as_slice())
    }

    fn diffie_hellman(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::RawSharedSecret, hpke::HpkeError> {
        let private_key = X448PrivateKey::from_array(**private_key);
        derive_x448_shared_secret(&private_key, *public_key)
            .map_err(|_| hpke::HpkeError::EncapError)
    }

    fn shared_secret_bytes(secret: &Self::RawSharedSecret) -> &[u8] {
        secret.as_bytes()
    }
}
