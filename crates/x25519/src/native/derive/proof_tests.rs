// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{agree, derive_x25519_shared_secret, release_shared_secret};
use crypto_core::contract_constants::x25519::{X25519_PRIVATE_KEY_LEN, X25519_PUBLIC_KEY_LEN};
use crypto_core::CryptoError;
use zeroize::Zeroizing;

#[kani::proof]
#[kani::unwind(65)]
fn x25519_release_requires_backend_contribution() {
    let bytes: [u8; X25519_PUBLIC_KEY_LEN] = kani::any();
    let contributory: bool = kani::any();
    match release_shared_secret(&bytes, contributory) {
        Ok(secret) => {
            assert!(contributory);
            assert_eq!(secret.as_slice(), &bytes);
        }
        Err(error) => {
            assert!(!contributory);
            assert_eq!(error, CryptoError::PRIMITIVE_INVALID_SHARED_SECRET);
        }
    }
}

#[kani::proof]
#[kani::stub(agree, unexpected_agreement)]
fn x25519_rejects_mismatched_key_lengths_before_agreement() {
    let private: [u8; X25519_PRIVATE_KEY_LEN + 1] = kani::any();
    let public: [u8; X25519_PUBLIC_KEY_LEN + 1] = kani::any();
    let private_len: usize = kani::any();
    let public_len: usize = kani::any();
    kani::assume(private_len <= private.len() && public_len <= public.len());
    kani::assume(private_len != X25519_PRIVATE_KEY_LEN || public_len != X25519_PUBLIC_KEY_LEN);
    assert_eq!(
        derive_x25519_shared_secret(&private[..private_len], &public[..public_len]).err(),
        Some(CryptoError::PRIMITIVE_INVALID_KEY),
    );
}

fn unexpected_agreement(
    _: &mut [u8; X25519_PRIVATE_KEY_LEN],
    _: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    kani::assert(false, "wrong-length keys must never reach agreement");
    Err(CryptoError::PRIMITIVE_INVALID_KEY)
}
