// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kani-only proof crate for the external-vector reference DER encoder.
//!
//! The proof lane deliberately reuses the production audit tool's `refenc.rs`
//! source file directly, while keeping Kani away from the full audit adapter
//! dependency graph. Kani 0.67 currently ships a Rust 1.93 verification
//! toolchain, below the release workspace's Rust 1.96 floor; this tiny crate
//! preserves the proof without weakening the main workspace MSRV.

#![forbid(unsafe_code)]

pub mod support;

#[path = "../../src/refenc.rs"]
pub mod refenc;
