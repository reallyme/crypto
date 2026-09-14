// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.ProviderException

internal fun bestEffortDelete(alias: String) {
    try {
        val store = loadKeyStore()
        if (store.containsAlias(alias)) {
            store.deleteEntry(alias)
        }
    } catch (_: Exception) {
        // The original typed failure remains authoritative. A subsequent
        // operation will still reject the duplicate persistent alias.
    }
}

internal fun mapPlatformError(error: Throwable): ReallyMeCryptoException =
    when {
        error is UserNotAuthenticatedException ->
            ReallyMeCryptoException.PlatformAuthenticationRequired()
        error is KeyPermanentlyInvalidatedException || error is InvalidKeyException ->
            ReallyMeCryptoException.HardwareRejectedKey()
        error.javaClass.name == STRONGBOX_UNAVAILABLE_EXCEPTION ->
            ReallyMeCryptoException.HardwareUnavailable()
        error is NoSuchAlgorithmException || error is NoSuchProviderException ->
            ReallyMeCryptoException.UnsupportedPlatform()
        else -> ReallyMeCryptoException.ProviderFailure()
    }

internal inline fun <T> withMappedPlatformErrors(operation: () -> T): T =
    try {
        operation()
    } catch (error: ReallyMeCryptoException) {
        throw error
    } catch (error: GeneralSecurityException) {
        throw mapPlatformError(error)
    } catch (error: ProviderException) {
        throw mapPlatformError(error)
    } catch (error: Exception) {
        throw mapPlatformError(error)
    }

internal class ResolvedHandle(
    val alias: String,
    val purpose: ReallyMeAndroidPlatformKeyPurpose,
    val actualSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
)
