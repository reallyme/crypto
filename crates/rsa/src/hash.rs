// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::types::RsaHash;

pub(crate) fn digest_message(hash: RsaHash, message: &[u8]) -> Vec<u8> {
    match hash {
        RsaHash::Sha1 => Sha1::digest(message).to_vec(),
        RsaHash::Sha256 => Sha256::digest(message).to_vec(),
        RsaHash::Sha384 => Sha384::digest(message).to_vec(),
        RsaHash::Sha512 => Sha512::digest(message).to_vec(),
    }
}

pub(crate) fn digest_len(hash: RsaHash) -> usize {
    match hash {
        RsaHash::Sha1 => 20,
        RsaHash::Sha256 => 32,
        RsaHash::Sha384 => 48,
        RsaHash::Sha512 => 64,
    }
}

pub(crate) fn mgf1_xor(mask: &mut [u8], hash: RsaHash, seed: &[u8]) -> Result<(), CryptoError> {
    let iterations = mask
        .len()
        .checked_add(
            digest_len(hash)
                .checked_sub(1)
                .ok_or(CryptoError::Signature {
                    backend: SignatureBackend::Native,
                    operation: SignatureOperation::Verify,
                    kind: SignatureFailureKind::InvalidSignature,
                })?,
        )
        .ok_or(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })?
        / digest_len(hash);

    let max_iterations = usize::try_from(u32::MAX).map_err(|_| CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    })?;

    if iterations > max_iterations {
        return Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        });
    }

    let mut offset = 0usize;
    for counter in 0..iterations {
        let counter_u32 = u32::try_from(counter).map_err(|_| CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })?;
        let digest = mgf1_digest(hash, seed, counter_u32);
        for byte in digest {
            if offset >= mask.len() {
                break;
            }
            mask[offset] ^= byte;
            offset = offset.checked_add(1).ok_or(CryptoError::Signature {
                backend: SignatureBackend::Native,
                operation: SignatureOperation::Verify,
                kind: SignatureFailureKind::InvalidSignature,
            })?;
        }
    }

    Ok(())
}

fn mgf1_digest(hash: RsaHash, seed: &[u8], counter: u32) -> Vec<u8> {
    let counter_bytes = counter.to_be_bytes();
    match hash {
        RsaHash::Sha1 => {
            let mut digest = Sha1::new();
            digest.update(seed);
            digest.update(counter_bytes);
            digest.finalize().to_vec()
        }
        RsaHash::Sha256 => {
            let mut digest = Sha256::new();
            digest.update(seed);
            digest.update(counter_bytes);
            digest.finalize().to_vec()
        }
        RsaHash::Sha384 => {
            let mut digest = Sha384::new();
            digest.update(seed);
            digest.update(counter_bytes);
            digest.finalize().to_vec()
        }
        RsaHash::Sha512 => {
            let mut digest = Sha512::new();
            digest.update(seed);
            digest.update(counter_bytes);
            digest.finalize().to_vec()
        }
    }
}
