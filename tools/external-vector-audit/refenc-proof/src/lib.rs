// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Kani-only proof crate for the external-vector reference DER encoder.
//!
//! The proof lane deliberately reuses the production audit tool's `refenc.rs`
//! source file directly, while keeping Kani away from the full audit adapter
//! dependency graph. Kani 0.67 currently ships a Rust 1.93 verification
//! toolchain, below the release workspace's Rust 1.96 floor; this tiny crate
//! preserves the proof without weakening the main workspace MSRV.

#![forbid(unsafe_code)]

/// Minimal, secret-free error vocabulary required by the shared reference
/// encoder. The full audit adapter crate has additional file and JSON errors;
/// Kani only needs shape and mismatch reasons for the encoder invariants.
pub mod support {
    /// Fixed errors emitted by the standalone reference-encoder proof crate.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AuditError {
        /// Encoded bytes do not match the expected invariant.
        Mismatch,
        /// Input or encoded shape is unsupported by this bounded proof.
        Shape,
    }
}

#[path = "../../src/refenc.rs"]
pub mod refenc;
