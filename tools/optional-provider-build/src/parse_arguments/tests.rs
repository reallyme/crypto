// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse, target};
use crate::ProviderBuildError;

#[test]
fn arguments_are_bounded_and_exact() {
    let valid = [
        "--target",
        "aarch64-apple-ios",
        "--out-dir",
        "/tmp/provider",
    ];
    assert!(parse(valid.map(Into::into)).is_ok());
    assert!(matches!(
        parse([].into_iter()),
        Err(ProviderBuildError::InvalidArguments)
    ));
    assert!(matches!(
        parse(
            [
                "--target",
                "wasm32-unknown-unknown",
                "--out-dir",
                "/tmp/provider"
            ]
            .map(Into::into)
        ),
        Err(ProviderBuildError::UnsupportedTarget)
    ));
    assert!(matches!(
        parse(
            [
                "--target",
                "aarch64-apple-ios",
                "--out-dir",
                "/tmp/with space"
            ]
            .map(Into::into)
        ),
        Err(ProviderBuildError::InvalidOutputPath)
    ));
    assert!(matches!(
        parse(
            [
                "--target",
                "aarch64-apple-ios",
                "--out-dir",
                "/tmp/provider",
                "extra"
            ]
            .map(Into::into)
        ),
        Err(ProviderBuildError::InvalidArguments)
    ));
    for value in [
        "aarch64-apple-ios-sim",
        "x86_64-apple-ios",
        "armv7-linux-androideabi",
        "i686-linux-android",
        "x86_64-linux-android",
    ] {
        assert!(target(value).is_ok());
    }
}
