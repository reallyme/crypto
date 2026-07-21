// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! KMAC256 implementation and typed secret-material owners.

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};
use sha3_kmac::Kmac256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Minimum KMAC256 key length required by its 256-bit security-strength
/// instantiation.
pub const KMAC256_MIN_KEY_LENGTH: usize = 32;

/// Maximum KMAC256 key length accepted by the public primitive.
///
/// Key-derivation keys are compact cryptographic material. The cap prevents
/// attacker-controlled allocation when a boundary copies the key into its
/// zeroizing owner.
pub const KMAC256_MAX_KEY_LENGTH: usize = 4_096;

/// Maximum protocol context length accepted by the public primitive.
pub const KMAC256_MAX_CONTEXT_LENGTH: usize = 65_536;

/// Maximum KMAC customization-string length accepted by the public primitive.
pub const KMAC256_MAX_CUSTOMIZATION_LENGTH: usize = 4_096;

/// Maximum output accepted by the public primitive.
///
/// Protocols normally derive compact traffic or wrapping keys. Bounding the
/// output prevents attacker-controlled allocation when this API is used behind
/// an FFI or protobuf adapter.
pub const KMAC256_MAX_OUTPUT_LENGTH: usize = 65_536;

/// Secret KMAC256 key-derivation key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Kmac256Key {
    bytes: Zeroizing<Vec<u8>>,
}

impl Kmac256Key {
    /// Constructs a KMAC256 key after enforcing the minimum security-strength
    /// length.
    ///
    /// # Errors
    ///
    /// Returns a typed KDF error when `input` is outside the accepted key
    /// length range.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if !(KMAC256_MIN_KEY_LENGTH..=KMAC256_MAX_KEY_LENGTH).contains(&input.len()) {
            return Err(kmac_error(KdfFailureKind::InvalidSecretLength));
        }

        Ok(Self {
            bytes: Zeroizing::new(input.to_vec()),
        })
    }

    /// Borrows the secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Output from KMAC256 key derivation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Kmac256Output {
    bytes: Zeroizing<Vec<u8>>,
}

impl Kmac256Output {
    /// Borrows the derived key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the derived-key length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the output is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Derives `output_length` bytes with KMAC256.
///
/// `context` is the SP 800-185 KMAC input string `X`; `customization` is the
/// customization string `S`. Protocols must construct and serialize their
/// context deterministically before calling this primitive. This API is not
/// the separately specified SP 800-108 KMAC-based key-derivation construction.
///
/// # Errors
///
/// Returns a typed KDF error for an empty or oversized output request or if
/// the backend rejects the key.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn derive_kmac256(
    key: &Kmac256Key,
    context: &[u8],
    customization: &[u8],
    output_length: usize,
) -> Result<Kmac256Output, CryptoError> {
    if output_length == 0 || output_length > KMAC256_MAX_OUTPUT_LENGTH {
        return Err(kmac_error(KdfFailureKind::InvalidOutputLength));
    }
    if context.len() > KMAC256_MAX_CONTEXT_LENGTH
        || customization.len() > KMAC256_MAX_CUSTOMIZATION_LENGTH
    {
        return Err(kmac_error(KdfFailureKind::InvalidParams));
    }

    let mut kmac = Kmac256::new(key.as_bytes(), customization)
        .map_err(|_| kmac_error(KdfFailureKind::InvalidSecretLength))?;
    kmac.update(context);
    let mut output = Zeroizing::new(vec![0u8; output_length]);
    kmac.finalize_into(&mut output);
    Ok(Kmac256Output { bytes: output })
}

fn kmac_error(kind: KdfFailureKind) -> CryptoError {
    CryptoError::Kdf {
        algorithm: KdfAlgorithm::Kmac256,
        profile: KdfProfile::Sp800185Kmac256,
        kind,
    }
}
