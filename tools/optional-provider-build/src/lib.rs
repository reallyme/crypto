// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build the pinned C library for an explicitly selected native provider.

#[cfg(not(target_arch = "wasm32"))]
mod build_provider;
mod error;
#[cfg(not(target_arch = "wasm32"))]
mod parse_arguments;
mod run;

pub use error::ProviderBuildError;
pub use run::run;
