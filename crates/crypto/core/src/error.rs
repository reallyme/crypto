// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical schema-defined failures shared by every crypto layer.

mod taxonomy;

pub use self::taxonomy::{CryptoError, CryptoErrorBranch, CryptoErrorReason};
