// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone schema adapters for the native const-generic HKDF operation.

use crate::proto_options::HkdfDeriveInputs;
use crate::{DeriveRequest, HkdfOutput};
use buffa::MessageField;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfNativeDeriveRequest, CryptoHkdfNativeDeriveResult, CryptoHkdfSuiteIdentifier,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected inputs bound to one unchanged native HKDF output width.
///
/// Schema validation checks the request shape and its agreement with `N`.
/// Suite admission, zero-length rejection and expansion errors remain owned by
/// [`crate::derive`], including the optional SHA3 execution feature.
pub struct HkdfNativeDeriveInputs<const N: usize> {
    inputs: HkdfDeriveInputs,
}

impl<const N: usize> HkdfNativeDeriveInputs<N> {
    /// Borrows the exact native inputs, preserving optional salt presence.
    pub fn as_request(&self) -> DeriveRequest<'_> {
        self.inputs.as_request()
    }

    /// Derives directly into the native clearing output owner.
    pub fn derive(&self) -> Result<HkdfOutput<N>, CryptoError> {
        crate::derive::<N>(&self.as_request())
    }

    /// Derives and copies through the final clearing schema result owner.
    ///
    /// The native operation must succeed before allocating the result storage.
    /// This preserves its suite-specific limits and errors without introducing
    /// a second output policy or a caller-sized allocating expansion function.
    pub fn derive_result(&self) -> Result<CryptoHkdfNativeDeriveResult, CryptoError> {
        let derived = self.derive()?;
        let mut result = CryptoHkdfNativeDeriveResult {
            suite: MessageField::some(CryptoHkdfSuiteIdentifier::from(self.as_request().suite)),
            derived_key: Default::default(),
        };
        result
            .derived_key
            .try_reserve_exact(N)
            .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
        result.derived_key.resize(N, 0)?;
        result.derived_key.copy_from_slice(derived.as_bytes());
        Ok(result)
    }
}

impl<const N: usize> TryFrom<&CryptoHkdfNativeDeriveRequest> for HkdfNativeDeriveInputs<N> {
    type Error = CryptoError;

    fn try_from(request: &CryptoHkdfNativeDeriveRequest) -> Result<Self, Self::Error> {
        let output_length = usize::try_from(request.output_length)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)?;
        if output_length != N {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        let inputs = request
            .inputs
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?;
        Ok(Self {
            inputs: HkdfDeriveInputs::try_from(inputs)?,
        })
    }
}

impl<const N: usize> Zeroize for HkdfNativeDeriveInputs<N> {
    fn zeroize(&mut self) {
        self.inputs.zeroize();
    }
}

// The contained input owners implement actual drop cleanup on every exit.
impl<const N: usize> ZeroizeOnDrop for HkdfNativeDeriveInputs<N> {}
