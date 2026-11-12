// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Fixed build-tool errors without paths or subprocess diagnostics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderBuildError {
    /// Arguments do not match the documented interface.
    #[error("invalid provider build arguments")]
    InvalidArguments,
    /// The target is outside the supported build set.
    #[error("unsupported provider build target")]
    UnsupportedTarget,
    /// The host cannot run this build tool.
    #[error("unsupported provider build host")]
    UnsupportedHost,
    /// The output path is unsuitable for the native build system.
    #[error("invalid provider output path")]
    InvalidOutputPath,
    /// The source package differs from the reviewed pin.
    #[error("unexpected provider source version")]
    SourceVersionMismatch,
    /// Native compilation failed.
    #[error("native provider build failed")]
    BuildFailed,
    /// The build record could not be written.
    #[error("provider build record failed")]
    RecordFailed,
}
