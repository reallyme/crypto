// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Darwin

/// Managed-runtime memory hygiene helpers.
public enum ReallyMeCryptoMemory {
    /// Overwrite a caller-owned Swift byte array in place on a best-effort basis.
    ///
    /// Swift arrays can be copied by ARC, optimizer, framework, or provider
    /// boundaries. This helper clears the supplied storage view; it does not
    /// guarantee removal of historical copies or values already handed to
    /// CryptoKit, Security, protobuf, or Rust FFI.
    public static func bestEffortClear(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
            guard let baseAddress = buffer.baseAddress else {
                return
            }

            // `memset_s` is specified to perform the writes even when the
            // optimizer can prove that Swift will not read this storage again.
            // The fallback preserves the public best-effort contract if the C
            // runtime unexpectedly rejects inputs that satisfy its bounds.
            let status = memset_s(baseAddress, buffer.count, 0, buffer.count)
            if status != 0 {
                for index in buffer.indices {
                    buffer[index] = 0
                }
            }
        }
    }
}
