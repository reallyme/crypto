// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::OperationFamily;

/// Platform-owned key operations represented by the shared domain model.
///
/// This enum is intentionally descriptive rather than executable. Apple and
/// Android SDK providers retain custody of platform key handles and must fail
/// closed when an operation is unavailable; the Rust core must never substitute
/// an exportable software key for a platform-owned key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PlatformKeyOperation {
    /// Generate a new non-exportable platform key.
    Generate,
    /// Return the public half of an existing platform key.
    GetPublicKey,
    /// Sign with an existing platform key.
    Sign,
    /// Verify with an existing platform key.
    Verify,
    /// Derive a shared secret with an existing platform key.
    DeriveSharedSecret,
    /// Delete an existing platform key.
    Delete,
    /// Request provider attestation for an existing platform key.
    Attest,
}

impl PlatformKeyOperation {
    /// Returns the semantic operation family used by policy and telemetry.
    #[must_use]
    pub const fn family(self) -> OperationFamily {
        OperationFamily::PlatformKey
    }

    /// Returns whether the operation requires a previously created key handle.
    #[must_use]
    pub const fn requires_existing_key(self) -> bool {
        !matches!(self, Self::Generate)
    }

    /// Returns whether successful execution can produce secret material.
    ///
    /// Callers use this classification to require a zeroizing managed owner for
    /// the shared-secret result before crossing an SDK or FFI boundary.
    #[must_use]
    pub const fn produces_secret_material(self) -> bool {
        matches!(self, Self::DeriveSharedSecret)
    }
}
