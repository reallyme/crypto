// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{AlgorithmKeypair, KeypairResultExt};
use crypto_core::{Algorithm, CryptoError, CryptoErrorReason};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[test]
fn fallible_keypair_adapter_preserves_every_known_canonical_reason() -> Result<(), CryptoError> {
    for &reason in CryptoErrorReason::VALUES {
        let error = CryptoError::try_new(reason);
        if reason.code() == 0 {
            assert_eq!(error, Err(CryptoError::PRIMITIVE_INVALID_PARAMETER));
            continue;
        }
        let error = error?;
        let source: Result<AlgorithmKeypair, CryptoError> = Err(error);
        assert_eq!(
            source.into_algorithm_keypair(Algorithm::Ed25519).err(),
            Some(error)
        );
    }
    Ok(())
}

#[test]
fn both_keypair_adapter_paths_preserve_the_secret_clearing_owner() -> Result<(), CryptoError> {
    fn require_cleanup<T: ZeroizeOnDrop>(_: &T) {}
    let direct: AlgorithmKeypair = (vec![0x11; 32], Zeroizing::new(vec![0x22; 32]));
    let (public, secret) = direct.into_algorithm_keypair(Algorithm::Ed25519)?;
    require_cleanup(&secret);
    assert_eq!(public, [0x11; 32]);
    assert_eq!(secret.as_slice(), &[0x22; 32]);

    let fallible: Result<AlgorithmKeypair, CryptoError> =
        Ok((vec![0x33; 32], Zeroizing::new(vec![0x44; 32])));
    let (public, secret) = fallible.into_algorithm_keypair(Algorithm::Ed25519)?;
    require_cleanup(&secret);
    assert_eq!(public, [0x33; 32]);
    assert_eq!(secret.as_slice(), &[0x44; 32]);
    Ok(())
}
