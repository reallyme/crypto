// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * Managed-runtime memory hygiene helpers.
 */
public object ReallyMeCryptoMemory {
    /**
     * Overwrite a caller-owned JVM byte array in place on a best-effort basis.
     *
     * JVM and Android runtimes may copy, compact, snapshot, or otherwise retain
     * historical copies of arrays. This helper clears the supplied array only;
     * it does not guarantee removal of copies already made by the runtime,
     * providers, JNI, protobuf, crash reporters, or application logging.
     */
    @JvmStatic
    public fun bestEffortClear(bytes: ByteArray) {
        bytes.fill(0)
    }
}
