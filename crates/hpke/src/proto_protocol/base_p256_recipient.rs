// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-profile recipient lifecycle returns the existing non-exportable owner.

use super::requests::copy_into;
use crate::base_p256::{P256BaseRng, P256RecipientKey, PRIVATE_KEY_LEN};
use crate::HpkeError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHpkeP256BasePublicKey, CryptoHpkeP256BaseRecipientGenerateRequest,
    CryptoHpkeP256BaseRecipientImportRequest,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Existing non-exportable native recipient and its public-only descriptor.
/// This is not a serialized private key, reusable context or registry handle.
///
/// ```compile_fail
/// fn duplicate(value: &crypto_hpke::base_p256::P256RecipientKey) -> crypto_hpke::base_p256::P256RecipientKey { value.clone() }
/// ```
/// ```compile_fail
/// fn serialize(value: &crypto_hpke::base_p256::P256RecipientKey) { let _ = serde_json::to_vec(value); }
/// ```
/// ```compile_fail
/// fn disclose(value: &crypto_hpke::base_p256::P256RecipientKey) { let _ = format!("{value:?}"); }
/// ```
pub type P256BaseRecipientOutput = (P256RecipientKey, CryptoHpkeP256BasePublicKey);

/// Owns the exact imported scalar until the unchanged native import validates it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256BaseRecipientImportInputs {
    private_key: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
}

impl P256BaseRecipientImportInputs {
    /// Imports into the fixed profile's existing non-exportable native owner.
    pub fn import(&self) -> Result<P256BaseRecipientOutput, HpkeError> {
        with_public_descriptor(P256RecipientKey::import(self.private_key.as_slice())?)
    }
}

impl TryFrom<&CryptoHpkeP256BaseRecipientImportRequest> for P256BaseRecipientImportInputs {
    type Error = HpkeError;

    fn try_from(value: &CryptoHpkeP256BaseRecipientImportRequest) -> Result<Self, Self::Error> {
        if value.private_key.len() != PRIVATE_KEY_LEN {
            return Err(HpkeError::PRIMITIVE_INVALID_PRIVATE_KEY);
        }
        let mut owner = Self {
            private_key: Zeroizing::new([0; PRIVATE_KEY_LEN]),
        };
        // The exact-width check precedes the fixed-array copy. Range validation
        // remains native and no scalar normalization or padding is performed.
        owner.private_key.copy_from_slice(&value.private_key);
        Ok(owner)
    }
}

/// Empty fixed-profile generation request; RNGs remain explicit native capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256BaseRecipientGenerateInputs;

impl P256BaseRecipientGenerateInputs {
    /// Uses the unchanged native operating-system entropy path.
    pub fn generate(&self) -> Result<P256BaseRecipientOutput, HpkeError> {
        with_public_descriptor(P256RecipientKey::generate()?)
    }

    /// Borrows the caller's native cryptographic entropy provider explicitly.
    /// The request cannot supply serialized RNG state or weaken provider policy.
    pub fn generate_with_rng(
        &self,
        rng: &mut impl P256BaseRng,
    ) -> Result<P256BaseRecipientOutput, HpkeError> {
        with_public_descriptor(P256RecipientKey::generate_with_rng(rng)?)
    }
}

impl TryFrom<&CryptoHpkeP256BaseRecipientGenerateRequest> for P256BaseRecipientGenerateInputs {
    type Error = HpkeError;

    fn try_from(_: &CryptoHpkeP256BaseRecipientGenerateRequest) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

fn with_public_descriptor(
    recipient: P256RecipientKey,
) -> Result<P256BaseRecipientOutput, HpkeError> {
    let mut descriptor = CryptoHpkeP256BasePublicKey::default();
    copy_into(&mut descriptor.public_key, recipient.public_key())?;
    Ok((recipient, descriptor))
}
