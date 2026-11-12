// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command-line entry point for the optional native provider build.

fn main() -> Result<(), optional_provider_build::ProviderBuildError> {
    optional_provider_build::run(std::env::args_os().skip(1))
}
