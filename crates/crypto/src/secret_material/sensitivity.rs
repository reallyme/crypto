// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Sensitivity classification for operation material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretSensitivity {
    /// Public material that does not require secret-memory handling.
    Public,
    /// Privacy-sensitive material, including plaintext and ciphertext.
    Sensitive,
    /// Cryptographic secret material requiring deterministic zeroization.
    Secret,
}
