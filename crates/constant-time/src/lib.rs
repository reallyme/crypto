// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Constant-time equality helpers built on `subtle`, for comparing secrets and authentication tags without data-dependent branches.

#![forbid(unsafe_code)]

/// Protected protobuf inputs and existing native helper contracts.
#[cfg(feature = "proto")]
pub mod proto_helpers;

mod compare;

pub use compare::{ct_eq, ct_eq_fixed, require_ct_eq};
