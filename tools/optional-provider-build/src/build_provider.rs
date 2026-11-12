// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fs::File, io::Write};

use crate::{parse_arguments::Options, ProviderBuildError};

const SOURCE_PACKAGE_VERSION: &str = "400.0.2+4.0.3";

pub(super) fn build(options: &Options) -> Result<(), ProviderBuildError> {
    if openssl_src::version() != SOURCE_PACKAGE_VERSION {
        return Err(ProviderBuildError::SourceVersionMismatch);
    }
    let host = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        _ => return Err(ProviderBuildError::UnsupportedHost),
    };
    let artifacts = openssl_src::Build::new()
        .host(host)
        .target(options.target)
        .out_dir(&options.output)
        .try_build()
        .map_err(|_| ProviderBuildError::BuildFailed)?;
    let record_path = artifacts.lib_dir().join("provider-source.txt");
    let mut record = File::create(record_path).map_err(|_| ProviderBuildError::RecordFailed)?;
    record
        .write_all(b"source-package=400.0.2+4.0.3\n")
        .map_err(|_| ProviderBuildError::RecordFailed)?;
    record
        .write_all(b"target=")
        .map_err(|_| ProviderBuildError::RecordFailed)?;
    record
        .write_all(options.target.as_bytes())
        .map_err(|_| ProviderBuildError::RecordFailed)?;
    record
        .write_all(b"\n")
        .map_err(|_| ProviderBuildError::RecordFailed)?;
    Ok(())
}
