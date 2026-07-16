// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Managed-runtime memory hygiene helpers.
public enum ReallyMeCryptoMemory {
    /// Overwrite a caller-owned Swift byte array in place on a best-effort basis.
    ///
    /// Swift arrays can be copied by ARC, optimizer, framework, or provider
    /// boundaries. This helper clears the supplied storage view; it does not
    /// guarantee removal of historical copies or values already handed to
    /// CryptoKit, Security, protobuf, or Rust FFI.
    public static func bestEffortClear(_ bytes: inout [UInt8]) {
        for index in bytes.indices {
            bytes[index] = 0
        }
    }
}
