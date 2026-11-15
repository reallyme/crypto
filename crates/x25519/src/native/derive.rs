// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::contract_constants::x25519::{X25519_PRIVATE_KEY_LEN, X25519_PUBLIC_KEY_LEN};
use crypto_core::CryptoError;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Derive an X25519 shared secret.
///
/// `shared_secret = X25519(secret_key, public_key)`
///
/// Non-contributory (all-zero) outputs are rejected: a low-order peer public
/// key drives the shared secret to zero, which would silently agree a
/// world-known secret. Failing closed here means callers do not have to
/// depend on a downstream KDF to catch a poisoned key exchange.
///
/// The shared secret is returned in a zeroizing wrapper so it is wiped when
/// the caller drops it.
pub fn derive_x25519_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let pk_bytes: &[u8; X25519_PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;

    let mut sk_bytes: [u8; X25519_PRIVATE_KEY_LEN] = secret_key
        .try_into()
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    agree(&mut sk_bytes, pk_bytes)
}

fn agree(
    sk_bytes: &mut [u8; X25519_PRIVATE_KEY_LEN],
    pk_bytes: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let sk = StaticSecret::from(*sk_bytes);
    // Wipe the stack copy of the secret scalar; `StaticSecret` owns its own
    // zeroize-on-drop copy from here on.
    sk_bytes.zeroize();
    let pk = PublicKey::from(*pk_bytes);

    let shared = sk.diffie_hellman(&pk);
    release_shared_secret(shared.as_bytes(), shared.was_contributory())
}

fn release_shared_secret(
    bytes: &[u8; X25519_PUBLIC_KEY_LEN],
    contributory: bool,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if !contributory {
        return Err(CryptoError::PRIMITIVE_INVALID_SHARED_SECRET);
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

#[cfg(kani)]
#[path = "derive/proof_tests.rs"]
mod proof_tests;
