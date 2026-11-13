// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected standalone contracts for the existing multikey dispatch helpers.
//!
//! These adapters preserve native feature selection and structural validation.
//! The generated result contains software secret bytes because the existing
//! native keypair operation already returns a caller-owned software secret.
//! No opaque key, provider handle or reusable context can be exported here.

mod convert_keypair;
mod copy_inputs;
mod encode_public_key;
mod validate_binding;

pub use convert_keypair::{GenerateMultikeyKeypairInputs, ProtectedGeneratedMultikeyKeypair};
pub use encode_public_key::PublicKeyToMultikeyInputs;
pub use validate_binding::VerificationMethodMultikeyInputs;
