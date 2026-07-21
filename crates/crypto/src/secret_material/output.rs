// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Security-relevant class of an operation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputMaterial {
    /// Digest, signature, public key, boolean, or other public result.
    Public,
    /// Ciphertext or wrapped material that remains privacy-sensitive.
    SensitivePublic,
    /// A private key, plaintext, shared secret, derived key, or seed.
    Secret,
    /// A structured result containing both public and secret fields.
    Mixed,
}
