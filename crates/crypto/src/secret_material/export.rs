// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Whether material may cross the operation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportPolicy {
    /// Public or ciphertext material may be returned without restriction.
    Public,
    /// Secret bytes may be returned only through an explicitly secret owner.
    SecretOwnerRequired,
    /// Provider-resident material must not be exported as raw bytes.
    NonExportable,
}
