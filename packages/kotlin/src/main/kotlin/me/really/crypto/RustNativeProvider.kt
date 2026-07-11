// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * Explicit loader for the ReallyMe Rust native provider.
 *
 * Rust-backed Kotlin primitives do not silently fall back to pure Kotlin or
 * platform providers. Applications load the audited `crypto-ffi` native library
 * once, then provider-aware algorithms such as Argon2id can call their JNI
 * entry points.
 */
public object ReallyMeRustNativeProvider {
    @Volatile
    private var loaded: Boolean = false

    public fun loadLibrary(path: String) {
        if (path.isEmpty()) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        try {
            System.load(path)
            loaded = true
        } catch (_: LinkageError) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: SecurityException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    internal fun requireLoaded() {
        if (!loaded) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }
}
