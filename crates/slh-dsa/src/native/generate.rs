// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN;
use crypto_core::{
    CryptoError, RngOutputKind, SignatureBackend, SignatureFailureKind, SignatureOperation,
};
use crypto_csprng::{generate_bytes, OsSecureRandom, SecureRandom};
use slh_dsa::signature::Keypair;
use slh_dsa::{Sha2_128s, SigningKey};
use zeroize::Zeroizing;

fn invalid_key_generation_seed() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::KeyManagement,
        kind: SignatureFailureKind::InvalidPrivateKey,
    }
}

/// Generate an SLH-DSA-SHA2-128s keypair.
pub fn generate_slh_dsa_sha2_128s_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    generate_slh_dsa_sha2_128s_keypair_with_rng(&mut OsSecureRandom)
}

fn generate_slh_dsa_sha2_128s_keypair_with_rng(
    rng: &mut impl SecureRandom,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    // FIPS 205 key generation consumes three independent n-byte strings. Draw
    // each through the audited OS-CSPRNG boundary so partial success is wiped
    // automatically and entropy failure remains a typed CryptoError::Rng.
    let sk_seed = generate_bytes::<SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN>(
        rng,
        RngOutputKind::SlhDsaSha2_128sSeed,
    )?;
    let sk_prf = generate_bytes::<SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN>(
        rng,
        RngOutputKind::SlhDsaSha2_128sSeed,
    )?;
    let pk_seed = generate_bytes::<SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN>(
        rng,
        RngOutputKind::SlhDsaSha2_128sSeed,
    )?;
    derive_slh_dsa_sha2_128s_keypair(sk_seed.as_bytes(), sk_prf.as_bytes(), pk_seed.as_bytes())
}

/// Derive an SLH-DSA-SHA2-128s keypair from the three FIPS 205 keygen seeds.
pub fn derive_slh_dsa_sha2_128s_keypair(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    if sk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        || sk_prf.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
        || pk_seed.len() != SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN
    {
        return Err(invalid_key_generation_seed());
    }

    let signing_key = SigningKey::<Sha2_128s>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
    let public_key = signing_key.verifying_key().to_vec();
    let secret_key = Zeroizing::new(signing_key.to_vec());

    Ok((public_key, secret_key))
}

#[cfg(test)]
mod tests {
    use super::generate_slh_dsa_sha2_128s_keypair_with_rng;
    use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
    use crypto_csprng::SecureRandom;

    struct UnavailableEntropy;

    impl SecureRandom for UnavailableEntropy {
        fn fill_secure(
            &mut self,
            _output: &mut [u8],
            kind: RngOutputKind,
        ) -> Result<(), CryptoError> {
            Err(CryptoError::Rng {
                output: kind,
                kind: RngFailureKind::EntropyUnavailable,
            })
        }
    }

    #[test]
    fn keygen_propagates_typed_entropy_failure() {
        let result = generate_slh_dsa_sha2_128s_keypair_with_rng(&mut UnavailableEntropy);
        assert!(matches!(
            result,
            Err(CryptoError::Rng {
                output: RngOutputKind::SlhDsaSha2_128sSeed,
                kind: RngFailureKind::EntropyUnavailable,
            })
        ));
    }
}
