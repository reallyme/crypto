// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{ffi::OsString, path::PathBuf};

use crate::ProviderBuildError;

pub(super) struct Options {
    pub(super) target: &'static str,
    pub(super) output: PathBuf,
}

pub(super) fn target(value: &str) -> Result<&'static str, ProviderBuildError> {
    match value {
        "aarch64-apple-darwin" => Ok("aarch64-apple-darwin"),
        "x86_64-apple-darwin" => Ok("x86_64-apple-darwin"),
        "aarch64-unknown-linux-gnu" => Ok("aarch64-unknown-linux-gnu"),
        "x86_64-unknown-linux-gnu" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64-apple-ios" => Ok("aarch64-apple-ios"),
        "aarch64-apple-ios-sim" => Ok("aarch64-apple-ios-sim"),
        "x86_64-apple-ios" => Ok("x86_64-apple-ios"),
        "aarch64-linux-android" => Ok("aarch64-linux-android"),
        "armv7-linux-androideabi" => Ok("armv7-linux-androideabi"),
        "i686-linux-android" => Ok("i686-linux-android"),
        "x86_64-linux-android" => Ok("x86_64-linux-android"),
        _ => Err(ProviderBuildError::UnsupportedTarget),
    }
}

pub(super) fn parse(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Options, ProviderBuildError> {
    const MAX_OUTPUT_PATH_LEN: usize = 4_096;
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--target")) {
        return Err(ProviderBuildError::InvalidArguments);
    }
    let target_arg = arguments
        .next()
        .ok_or(ProviderBuildError::InvalidArguments)?;
    let target = target(
        target_arg
            .to_str()
            .ok_or(ProviderBuildError::UnsupportedTarget)?,
    )?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--out-dir")) {
        return Err(ProviderBuildError::InvalidArguments);
    }
    let output_arg = arguments
        .next()
        .ok_or(ProviderBuildError::InvalidArguments)?;
    let output_text = output_arg
        .to_str()
        .ok_or(ProviderBuildError::InvalidOutputPath)?;
    // OpenSSL's generated makefiles do not support whitespace in build paths.
    if output_text.is_empty()
        || output_text.len() > MAX_OUTPUT_PATH_LEN
        || output_text
            .chars()
            .any(|value| value.is_whitespace() || value == '\0')
    {
        return Err(ProviderBuildError::InvalidOutputPath);
    }
    if arguments.next().is_some() {
        return Err(ProviderBuildError::InvalidArguments);
    }
    Ok(Options {
        target,
        output: PathBuf::from(output_arg),
    })
}

#[cfg(test)]
mod tests;
