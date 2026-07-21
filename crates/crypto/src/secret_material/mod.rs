// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Typed secret-material ownership and cleanup contracts.
//!
//! These records describe the security contract enforced by semantic
//! operation entry points. They never contain runtime key material.

mod destruction;
mod export;
mod output;
mod owner;
mod policy;
mod retention;
mod sensitivity;
mod zeroization;

pub use self::destruction::DestructionPolicy;
pub use self::export::ExportPolicy;
pub use self::output::OutputMaterial;
pub use self::owner::BufferOwner;
pub use self::policy::{
    operation_secret_material_policy, random_fill_secret_material_policy, MaterialPolicy,
    OperationSecretMaterialPolicy, SecretMaterialOperation,
};
pub use self::retention::RetentionPolicy;
pub use self::sensitivity::SecretSensitivity;
pub use self::zeroization::ZeroizationPolicy;

pub(crate) use self::policy::bind_operation_policy;
#[cfg(feature = "csprng")]
pub(crate) use self::policy::bind_random_fill_policy;
