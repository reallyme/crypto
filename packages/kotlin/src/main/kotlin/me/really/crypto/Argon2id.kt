// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * Argon2id key derivation backed by the ReallyMe Rust native provider.
 *
 * Android/JVM do not provide a stable OS Argon2id primitive. The package routes
 * this memory-hard KDF to Rust so Swift, Kotlin, TypeScript/WASM, and Rust all
 * share the same versioned cost profiles and output contract.
 */
public object ReallyMeArgon2id {
    public const val DERIVED_KEY_LENGTH: Int = 32
    public const val SALT_MIN_LENGTH: Int = 16
    public const val SALT_MAX_LENGTH: Int = 32
    public const val V1: UInt = 1u
    public const val V2: UInt = 2u

    public fun deriveKey(kdfVersion: UInt, secret: ByteArray, salt: ByteArray): ByteArray {
        validate(kdfVersion, secret, salt)
        ReallyMeRustNativeProvider.requireLoaded()
        return try {
            requireRustNativeBytes(deriveKeyNative(kdfVersion.toInt(), secret, salt))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: LinkageError) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: RuntimeException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    @JvmStatic
    private external fun deriveKeyNative(kdfVersion: Int, secret: ByteArray, salt: ByteArray): ByteArray?

    private fun validate(kdfVersion: UInt, secret: ByteArray, salt: ByteArray) {
        if (
            (kdfVersion != V1 && kdfVersion != V2) ||
            secret.isEmpty() ||
            salt.size !in SALT_MIN_LENGTH..SALT_MAX_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
