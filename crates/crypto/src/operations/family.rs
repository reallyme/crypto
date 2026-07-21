// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Operation families that will each receive one semantic implementation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OperationFamily {
    /// Hash digest operations.
    Hash,
    /// Constant-time comparison operations.
    ConstantTime,
    /// Message authentication code operations.
    Mac,
    /// Authenticated encryption operations.
    Aead,
    /// AES Key Wrap operations.
    KeyWrap,
    /// Key derivation operations.
    Kdf,
    /// Signature key management, signing, and verification operations.
    Signature,
    /// Raw key-agreement operations.
    KeyAgreement,
    /// Key encapsulation operations.
    Kem,
    /// HPKE seal/open protocol operations.
    Hpke,
    /// Hardware-backed platform-key lifecycle and use operations.
    PlatformKey,
}
