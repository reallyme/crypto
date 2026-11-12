// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ProviderBuildError;

/// Build the pinned provider with `--target TRIPLE --out-dir DIRECTORY`.
/// The install prefix is `DIRECTORY/install`; source and object files stay
/// under the supplied directory. Private key material is never processed.
#[cfg(not(target_arch = "wasm32"))]
pub fn run(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<(), ProviderBuildError> {
    let options = crate::parse_arguments::parse(arguments)?;
    crate::build_provider::build(&options)
}

/// The native build tool is compile-only on WASM and cannot spawn a compiler.
#[cfg(target_arch = "wasm32")]
pub fn run(_: impl IntoIterator<Item = std::ffi::OsString>) -> Result<(), ProviderBuildError> {
    Err(ProviderBuildError::UnsupportedHost)
}
