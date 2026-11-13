// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::types::RsaHash;

// The backend's finalized array has no clearing destructor. Guard it before
// copying into the returned owner, including when allocating that owner fails.
struct FinalizedDigestBytes<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> Zeroize for FinalizedDigestBytes<T> {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl<T: AsMut<[u8]>> Drop for FinalizedDigestBytes<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: AsMut<[u8]>> ZeroizeOnDrop for FinalizedDigestBytes<T> {}

pub(crate) fn digest_message(
    hash: RsaHash,
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    digest_parts(hash, &[message])
}

// Borrow segments so PSS and MGF1 retain their exact concatenation without
// building another unprotected input buffer or returning an unguarded digest.
pub(super) fn digest_parts(
    hash: RsaHash,
    parts: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match hash {
        RsaHash::Sha1 => digest_parts_with::<Sha1>(parts),
        RsaHash::Sha256 => digest_parts_with::<Sha256>(parts),
        RsaHash::Sha384 => digest_parts_with::<Sha384>(parts),
        RsaHash::Sha512 => digest_parts_with::<Sha512>(parts),
    }
}

fn digest_parts_with<D: Digest>(parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut digest = D::new();
    for part in parts {
        digest.update(part);
    }
    let finalized = FinalizedDigestBytes(digest.finalize());
    let source: &[u8] = finalized.0.as_ref();
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(source.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.extend_from_slice(source);
    Ok(output)
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
                .ok_or(crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)?,
        )
        .ok_or(crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)?
        / digest_len(hash);

    let max_iterations = usize::try_from(u32::MAX)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;

    if iterations > max_iterations {
        return Err(crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }

    let mut offset = 0usize;
    for counter in 0..iterations {
        let counter_u32 = u32::try_from(counter)
            .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
        let digest = digest_parts(hash, &[seed, &counter_u32.to_be_bytes()])?;
        // Borrow rather than consume the vector: its clearing owner must stay
        // alive through the final partial block and any early return.
        for byte in digest.iter() {
            if offset >= mask.len() {
                break;
            }
            mask[offset] ^= byte;
            offset = offset
                .checked_add(1)
                .ok_or(crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "hash_output_tests.rs"]
mod output_owner_tests;
