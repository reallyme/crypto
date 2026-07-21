// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * KMAC256 key derivation backed by the ReallyMe Rust native provider.
 *
 * JVM and Android do not provide a stable platform KMAC contract. Routing this
 * KDF through Rust keeps the KMAC byte contract identical to Rust, Swift, and
 * TypeScript/WASM.
 */
public object ReallyMeKmac {
    public const val MIN_KEY_LENGTH: Int = 32
    public const val MAX_KEY_LENGTH: Int = 4_096
    public const val MAX_CONTEXT_LENGTH: Int = 65_536
    public const val MAX_CUSTOMIZATION_LENGTH: Int = 4_096
    public const val MIN_OUTPUT_LENGTH: Int = 1
    public const val MAX_OUTPUT_LENGTH: Int = 65_536

    public fun deriveKmac256(
        key: ByteArray,
        context: ByteArray,
        customization: ByteArray,
        outputLength: Int,
    ): ByteArray {
        validate(key, context, customization, outputLength)
        ReallyMeRustNativeProvider.requireLoaded()
        return try {
            val derived =
                requireRustNativeBytes(
                    deriveKmac256Native(key, context, customization, outputLength),
                )
            if (derived.size != outputLength) {
                derived.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            derived
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: LinkageError) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: RuntimeException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    @JvmStatic
    private external fun deriveKmac256Native(
        key: ByteArray,
        context: ByteArray,
        customization: ByteArray,
        outputLength: Int,
    ): ByteArray?

    private fun validate(
        key: ByteArray,
        context: ByteArray,
        customization: ByteArray,
        outputLength: Int,
    ) {
        if (
            key.size < MIN_KEY_LENGTH ||
            key.size > MAX_KEY_LENGTH ||
            context.size > MAX_CONTEXT_LENGTH ||
            customization.size > MAX_CUSTOMIZATION_LENGTH ||
            outputLength < MIN_OUTPUT_LENGTH ||
            outputLength > MAX_OUTPUT_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }
}
