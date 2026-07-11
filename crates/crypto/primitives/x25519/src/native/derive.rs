// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
    if secret_key.len() != 32 || public_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let mut sk_bytes: [u8; 32] = secret_key.try_into().map_err(|_| CryptoError::InvalidKey)?;

    let pk_bytes: [u8; 32] = public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;

    let sk = StaticSecret::from(sk_bytes);
    // Wipe the stack copy of the secret scalar; `StaticSecret` owns its own
    // zeroize-on-drop copy from here on.
    sk_bytes.zeroize();
    let pk = PublicKey::from(pk_bytes);

    let shared = sk.diffie_hellman(&pk);
    if !shared.was_contributory() {
        return Err(CryptoError::KeyAgreementFailure {
            kind: crypto_core::KeyAgreementFailureKind::DeriveSharedSecretFailed,
        });
    }
    Ok(Zeroizing::new(shared.as_bytes().to_vec()))
}
