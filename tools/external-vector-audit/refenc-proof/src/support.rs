// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal, secret-free error vocabulary required by the shared reference
//! encoder. The full audit adapter crate has additional file and JSON errors;
//! Kani only needs shape and mismatch reasons for the encoder invariants.

/// Fixed errors emitted by the standalone reference-encoder proof crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    /// Encoded bytes do not match the expected invariant.
    Mismatch,
    /// Input or encoded shape is unsupported by this bounded proof.
    Shape,
}
