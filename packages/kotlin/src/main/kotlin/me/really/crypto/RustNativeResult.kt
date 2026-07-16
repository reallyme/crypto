// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * Compact status values returned by Rust JNI provider calls.
 *
 * The JNI byte envelope keeps native failures typed without exposing backend
 * exception text or user-controlled buffers. Kotlin maps these statuses into
 * facade exceptions for normal SDK use and into protobuf wire errors when the
 * caller needs lossless pass-through.
 */
public enum class ReallyMeNativeStatus(public val code: Int) {
    OK(0),
    INVALID_INPUT(1),
    AUTHENTICATION_FAILED(2),
    UNSUPPORTED_ALGORITHM(3),
    PROVIDER_UNAVAILABLE(4),
    BACKEND_INTERNAL(5),
    INVALID_SIGNATURE(6),
}

internal data class ReallyMeNativeResult(
    val status: ReallyMeNativeStatus,
    val bytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ReallyMeNativeResult) return false
        return status == other.status && bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = 31 * status.hashCode() + bytes.contentHashCode()
}

private const val NATIVE_STATUS_BYTES: Int = 4

internal fun decodeRustNativeResult(encoded: ByteArray?): ReallyMeNativeResult {
    if (encoded == null || encoded.size < NATIVE_STATUS_BYTES) {
        return ReallyMeNativeResult(ReallyMeNativeStatus.BACKEND_INTERNAL, ByteArray(0))
    }
    val statusCode =
        ((encoded[0].toInt() and 0xff) shl 24) or
            ((encoded[1].toInt() and 0xff) shl 16) or
            ((encoded[2].toInt() and 0xff) shl 8) or
            (encoded[3].toInt() and 0xff)
    val status = ReallyMeNativeStatus.entries.firstOrNull { it.code == statusCode }
        ?: ReallyMeNativeStatus.BACKEND_INTERNAL
    val payload = encoded.copyOfRange(NATIVE_STATUS_BYTES, encoded.size)
    encoded.fill(0)
    return ReallyMeNativeResult(status, payload)
}

internal fun requireRustNativeBytes(encoded: ByteArray?): ByteArray {
    val result = decodeRustNativeResult(encoded)
    if (result.status != ReallyMeNativeStatus.OK) {
        throw result.status.toFacadeError()
    }
    return result.bytes
}

public fun ReallyMeNativeStatus.toFacadeError(): ReallyMeCryptoException =
    when (this) {
        ReallyMeNativeStatus.OK -> ReallyMeCryptoException.ProviderFailure()
        ReallyMeNativeStatus.INVALID_INPUT -> ReallyMeCryptoException.InvalidInput()
        ReallyMeNativeStatus.AUTHENTICATION_FAILED -> ReallyMeCryptoException.AuthenticationFailed()
        ReallyMeNativeStatus.UNSUPPORTED_ALGORITHM -> ReallyMeCryptoException.UnsupportedAlgorithm()
        ReallyMeNativeStatus.PROVIDER_UNAVAILABLE,
        ReallyMeNativeStatus.BACKEND_INTERNAL,
        -> ReallyMeCryptoException.ProviderFailure()
        ReallyMeNativeStatus.INVALID_SIGNATURE -> ReallyMeCryptoException.InvalidSignature()
    }
