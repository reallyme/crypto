// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import org.bouncycastle.asn1.sec.SECNamedCurves
/**
 * Internal Android Keystore implementation shared by the public platform-key facade.
 *
 * Keeping provider mechanics outside the facade makes the exported API easy to audit while
 * retaining one package-private implementation path for validation and error mapping.
 */
internal const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
internal const val ANDROID_OPENSSL: String = "AndroidOpenSSL"
internal const val EC_ALGORITHM: String = "EC"
internal const val P256_CURVE: String = "secp256r1"
internal const val ECDH_ALGORITHM: String = "ECDH"
internal const val ECDSA_SHA256_ALGORITHM: String = "SHA256withECDSA"
internal const val HANDLE_VERSION: Byte = 1
internal const val HANDLE_LENGTH: Int = 39
internal const val HANDLE_SECURITY_LEVEL_OFFSET: Int = 6
internal const val HANDLE_DIGEST_OFFSET: Int = 7
internal const val DIGEST_LENGTH: Int = 32
internal const val SIGNING_PURPOSE_CODE: Byte = 1
internal const val KEY_AGREEMENT_PURPOSE_CODE: Byte = 2
internal const val STRONGBOX_UNAVAILABLE_EXCEPTION: String =
    "android.security.keystore.StrongBoxUnavailableException"
internal const val ALIAS_PREFIX: String = "me.really.crypto.platform-key.v1"
internal val handleMagic: ByteArray = byteArrayOf(0x52, 0x4d, 0x41, 0x4b)
internal val aliasDomain: ByteArray =
    "me.really.crypto.android-platform-key.v1".toByteArray(Charsets.US_ASCII)

@Synchronized
internal fun generateKeyPair(
    purpose: ReallyMeAndroidPlatformKeyPurpose,
    applicationTag: ByteArray,
    policy: ReallyMeAndroidPlatformKeyPolicy,
    overwriteExisting: Boolean,
): ReallyMeAndroidPlatformKeyPair {
    validateApplicationTag(applicationTag)
    validatePolicy(policy, purpose)
    requirePlatformKeyApi()

    val digest = applicationTagDigest(applicationTag, purpose)
    val alias = aliasFor(digest, purpose)
    var generationStarted = false
    try {
        val store = loadKeyStore()
        if (store.containsAlias(alias)) {
            if (!overwriteExisting) {
                throw ReallyMeCryptoException.PlatformKeyAlreadyExists()
            }
            store.deleteEntry(alias)
        }

        val generator = KeyPairGenerator.getInstance(EC_ALGORITHM, ANDROID_KEYSTORE)
        // Once generation starts, clean the alias on every failure. Some
        // Android Keystore providers can persist an entry before reporting
        // a late provider or attestation error.
        generationStarted = true
        generator.initialize(generationSpec(alias, purpose, policy))
        val keyPair = generator.generateKeyPair()
        val actualSecurityLevel = inspectPrivateKey(
            keyPair.private,
            purpose,
            expectedSecurityLevel = null,
        )
        enforceRequestedSecurityLevel(policy.requestedSecurityLevel, actualSecurityLevel)
        val handle = encodeHandle(digest, purpose, actualSecurityLevel)
        return try {
            ReallyMeAndroidPlatformKeyPair(
                purpose = purpose,
                requestedSecurityLevel = policy.requestedSecurityLevel,
                actualSecurityLevel = actualSecurityLevel,
                publicKey = compressedPublicKey(keyPair.public),
                privateKeyHandle = handle,
            )
        } finally {
            handle.fill(0)
        }
    } catch (error: ReallyMeCryptoException) {
        if (generationStarted) {
            bestEffortDelete(alias)
        }
        throw error
    } catch (error: GeneralSecurityException) {
        if (generationStarted) {
            bestEffortDelete(alias)
        }
        throw mapPlatformError(error)
    } catch (error: ProviderException) {
        if (generationStarted) {
            bestEffortDelete(alias)
        }
        throw mapPlatformError(error)
    } catch (error: Exception) {
        if (generationStarted) {
            bestEffortDelete(alias)
        }
        throw mapPlatformError(error)
    } finally {
        digest.fill(0)
    }
}

@TargetApi(31)
internal fun generationSpec(
    alias: String,
    purpose: ReallyMeAndroidPlatformKeyPurpose,
    policy: ReallyMeAndroidPlatformKeyPolicy,
): KeyGenParameterSpec {
    val builder = KeyGenParameterSpec.Builder(alias, keyPurpose(purpose))
        .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))

    if (purpose == ReallyMeAndroidPlatformKeyPurpose.SIGNING) {
        builder.setDigests(KeyProperties.DIGEST_SHA256)
    }
    if (policy.requestedSecurityLevel == ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX) {
        builder.setIsStrongBoxBacked(true)
    }

    builder.setUserAuthenticationRequired(policy.userAuthenticationRequired)
    if (policy.userAuthenticationRequired) {
        configureUserAuthentication(builder, policy)
        builder.setInvalidatedByBiometricEnrollment(policy.invalidatedByBiometricEnrollment)
    }
    if (policy.userConfirmationRequired) {
        builder.setUserConfirmationRequired(true)
    }
    if (policy.unlockedDeviceRequired) {
        builder.setUnlockedDeviceRequired(true)
    }

    val attestationChallenge = policy.attestationChallenge
    if (attestationChallenge != null) {
        // KeyGenParameterSpec owns the generation-time challenge after the
        // builder call. Do not clear this copy before key generation: the
        // platform contract does not guarantee an eager defensive copy.
        builder.setAttestationChallenge(attestationChallenge)
    }
    return builder.build()
}

internal fun validatePolicy(
    policy: ReallyMeAndroidPlatformKeyPolicy,
    purpose: ReallyMeAndroidPlatformKeyPurpose,
) {
    if (
        policy.userAuthenticationTimeoutSeconds !in
        0..ReallyMeAndroidPlatformKeys.MAX_AUTHENTICATION_TIMEOUT_SECONDS
    ) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    if (!policy.userAuthenticationRequired && policy.userAuthenticationTimeoutSeconds != 0) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    if (policy.userAuthenticationRequired &&
        !policy.allowBiometricStrong &&
        !policy.allowDeviceCredential
    ) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    if (policy.invalidatedByBiometricEnrollment &&
        (!policy.userAuthenticationRequired ||
            policy.userAuthenticationTimeoutSeconds != 0 ||
            !policy.allowBiometricStrong ||
            policy.allowDeviceCredential)
    ) {
        // Android only enforces enrollment invalidation for per-operation,
        // biometric-only keys. Reject policy combinations whose stated
        // security property the platform would silently ignore.
        throw ReallyMeCryptoException.InvalidInput()
    }
    if (policy.userConfirmationRequired &&
        purpose != ReallyMeAndroidPlatformKeyPurpose.SIGNING
    ) {
        // Protected Confirmation authenticates data that is subsequently
        // signed; it does not define a confirmation flow for ECDH.
        throw ReallyMeCryptoException.InvalidInput()
    }
    val challenge = policy.attestationChallenge
    // Attestation challenges are public nonces embedded in the certificate
    // chain. The policy getter returns a defensive copy, so wiping that
    // temporary would neither protect nor modify the policy-owned value.
    if (challenge != null &&
        challenge.size !in
        ReallyMeAndroidPlatformKeys.MIN_ATTESTATION_CHALLENGE_LENGTH..
            ReallyMeAndroidPlatformKeys.MAX_ATTESTATION_CHALLENGE_LENGTH
    ) {
        throw ReallyMeCryptoException.InvalidInput()
    }
}

internal fun validateApplicationTag(applicationTag: ByteArray) {
    if (
        applicationTag.size !in
        ReallyMeAndroidPlatformKeys.MIN_APPLICATION_TAG_LENGTH..
            ReallyMeAndroidPlatformKeys.MAX_APPLICATION_TAG_LENGTH
    ) {
        throw ReallyMeCryptoException.InvalidInput()
    }
}

internal fun requirePlatformKeyApi() {
    if (Build.VERSION.SDK_INT < 31) {
        throw ReallyMeCryptoException.UnsupportedPlatform()
    }
}

@TargetApi(31)
internal fun keyPurpose(purpose: ReallyMeAndroidPlatformKeyPurpose): Int =
    when (purpose) {
        ReallyMeAndroidPlatformKeyPurpose.SIGNING -> KeyProperties.PURPOSE_SIGN
        ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT -> KeyProperties.PURPOSE_AGREE_KEY
    }

@TargetApi(31)
internal fun configureUserAuthentication(
    builder: KeyGenParameterSpec.Builder,
    policy: ReallyMeAndroidPlatformKeyPolicy,
) {
    var authenticationTypes = 0
    if (policy.allowBiometricStrong) {
        authenticationTypes = authenticationTypes or KeyProperties.AUTH_BIOMETRIC_STRONG
    }
    if (policy.allowDeviceCredential) {
        authenticationTypes = authenticationTypes or KeyProperties.AUTH_DEVICE_CREDENTIAL
    }
    builder.setUserAuthenticationParameters(
        policy.userAuthenticationTimeoutSeconds,
        authenticationTypes,
    )
}

internal fun loadKeyStore(): KeyStore =
    KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

internal fun privateKeyEntry(alias: String): KeyStore.PrivateKeyEntry =
    privateKeyEntry(loadKeyStore(), alias)

internal fun privateKeyEntry(store: KeyStore, alias: String): KeyStore.PrivateKeyEntry {
    if (!store.containsAlias(alias)) {
        throw ReallyMeCryptoException.PlatformKeyNotFound()
    }
    return store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        ?: throw ReallyMeCryptoException.HardwareRejectedKey()
}

internal fun validatePrivateKey(
    privateKey: PrivateKey,
    purpose: ReallyMeAndroidPlatformKeyPurpose,
    expectedSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
) {
    inspectPrivateKey(privateKey, purpose, expectedSecurityLevel)
}

internal fun inspectPrivateKey(
    privateKey: PrivateKey,
    purpose: ReallyMeAndroidPlatformKeyPurpose,
    expectedSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel?,
): ReallyMeAndroidPlatformKeySecurityLevel {
    if (privateKey.encoded != null) {
        throw ReallyMeCryptoException.HardwareRejectedKey()
    }
    val keyFactory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
    val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
    val requiredPurpose = keyPurpose(purpose)
    if (keyInfo.keySize != 256 ||
        keyInfo.origin != KeyProperties.ORIGIN_GENERATED ||
        keyInfo.purposes and requiredPurpose != requiredPurpose
    ) {
        throw ReallyMeCryptoException.HardwareRejectedKey()
    }
    val actualSecurityLevel = exactHardwareSecurityLevel(keyInfo)
    if (expectedSecurityLevel != null && actualSecurityLevel != expectedSecurityLevel) {
        throw ReallyMeCryptoException.HardwareRejectedKey()
    }
    return actualSecurityLevel
}

@TargetApi(31)
internal fun exactHardwareSecurityLevel(
    keyInfo: KeyInfo,
): ReallyMeAndroidPlatformKeySecurityLevel =
    when (keyInfo.securityLevel) {
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
            ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_STRONGBOX ->
            ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX
        else -> throw ReallyMeCryptoException.HardwareUnavailable()
    }

internal fun enforceRequestedSecurityLevel(
    requested: ReallyMeAndroidPlatformKeySecurityLevel,
    actual: ReallyMeAndroidPlatformKeySecurityLevel,
) {
    if (requested == ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX &&
        actual != ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX
    ) {
        throw ReallyMeCryptoException.HardwareUnavailable()
    }
}

internal fun compressedPublicKey(publicKey: java.security.PublicKey): ByteArray {
    val ecPublicKey = publicKey as? ECPublicKey
        ?: throw ReallyMeCryptoException.HardwareRejectedKey()
    val x = unsignedFixed(
        ecPublicKey.w.affineX,
        ReallyMeAndroidPlatformKeys.SHARED_SECRET_LENGTH,
    )
    val prefix: Byte = if (ecPublicKey.w.affineY.testBit(0)) 0x03.toByte() else 0x02.toByte()
    return byteArrayOf(prefix) + x
}

internal fun decodeCompressedPublicKey(publicKey: ByteArray): java.security.PublicKey {
    if (publicKey.size != ReallyMeAndroidPlatformKeys.COMPRESSED_PUBLIC_KEY_LENGTH) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    val parameters = SECNamedCurves.getByName(P256_CURVE)
    val point = try {
        parameters.curve.decodePoint(publicKey).normalize()
    } catch (_: IllegalArgumentException) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    if (point.isInfinity) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    return withMappedPlatformErrors {
        val algorithmParameters = AlgorithmParameters.getInstance(EC_ALGORITHM).apply {
            init(ECGenParameterSpec(P256_CURVE))
        }
        val ecParameters = algorithmParameters.getParameterSpec(ECParameterSpec::class.java)
        // Android Keystore delegates the peer half of ECDH to the platform
        // EC provider. Some hardware implementations reject a valid
        // BouncyCastle ECPublicKey at doPhase even though its parameters
        // and encoding are standard. Decode and validate the point above,
        // then construct the public key with the platform provider so the
        // hardware operation receives the native key representation it
        // requires. The provider is named explicitly to avoid ambient JCA
        // provider-order changes.
        KeyFactory.getInstance(EC_ALGORITHM, ANDROID_OPENSSL).generatePublic(
            ECPublicKeySpec(
                ECPoint(
                    point.affineXCoord.toBigInteger(),
                    point.affineYCoord.toBigInteger(),
                ),
                ecParameters,
            ),
        )
    }
}

internal fun unsignedFixed(value: BigInteger, length: Int): ByteArray {
    val encoded = value.toByteArray()
    val first = when {
        encoded.size <= length -> 0
        encoded.size == length + 1 && encoded[0] == 0.toByte() -> 1
        else -> throw ReallyMeCryptoException.HardwareRejectedKey()
    }
    val copied = encoded.size - first
    val output = ByteArray(length)
    System.arraycopy(encoded, first, output, length - copied, copied)
    return output
}

internal fun applicationTagDigest(
    applicationTag: ByteArray,
    purpose: ReallyMeAndroidPlatformKeyPurpose,
): ByteArray =
    java.security.MessageDigest.getInstance("SHA-256").run {
        update(aliasDomain)
        update(0.toByte())
        update(purposeCode(purpose))
        digest(applicationTag)
    }

internal fun encodeHandle(
    digest: ByteArray,
    purpose: ReallyMeAndroidPlatformKeyPurpose,
    actualSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
): ByteArray {
    if (digest.size != DIGEST_LENGTH) {
        throw ReallyMeCryptoException.ProviderFailure()
    }
    val handle = ByteArray(HANDLE_LENGTH)
    System.arraycopy(handleMagic, 0, handle, 0, handleMagic.size)
    handle[4] = HANDLE_VERSION
    handle[5] = purposeCode(purpose)
    handle[HANDLE_SECURITY_LEVEL_OFFSET] = securityLevelCode(actualSecurityLevel)
    System.arraycopy(digest, 0, handle, HANDLE_DIGEST_OFFSET, digest.size)
    return handle
}

internal fun resolveHandle(
    privateKeyHandle: ByteArray,
    expectedPurpose: ReallyMeAndroidPlatformKeyPurpose? = null,
): ResolvedHandle {
    if (privateKeyHandle.size != HANDLE_LENGTH ||
        !privateKeyHandle.copyOfRange(0, handleMagic.size).contentEquals(handleMagic) ||
        privateKeyHandle[4] != HANDLE_VERSION
    ) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    val purpose = purposeFromCode(privateKeyHandle[5])
    val actualSecurityLevel = securityLevelFromCode(
        privateKeyHandle[HANDLE_SECURITY_LEVEL_OFFSET],
    )
    if (expectedPurpose != null && purpose != expectedPurpose) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    val digest = privateKeyHandle.copyOfRange(HANDLE_DIGEST_OFFSET, HANDLE_LENGTH)
    return try {
        ResolvedHandle(aliasFor(digest, purpose), purpose, actualSecurityLevel)
    } finally {
        digest.fill(0)
    }
}

internal fun aliasFor(
    digest: ByteArray,
    purpose: ReallyMeAndroidPlatformKeyPurpose,
): String {
    if (digest.size != DIGEST_LENGTH) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    val alphabet = "0123456789abcdef"
    val encoded = CharArray(digest.size * 2)
    digest.forEachIndexed { index, byte ->
        val value = byte.toInt() and 0xff
        encoded[index * 2] = alphabet[value ushr 4]
        encoded[index * 2 + 1] = alphabet[value and 0x0f]
    }
    val purposeLabel = when (purpose) {
        ReallyMeAndroidPlatformKeyPurpose.SIGNING -> "signing"
        ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT -> "agreement"
    }
    return "$ALIAS_PREFIX.$purposeLabel.${String(encoded)}"
}

internal fun purposeCode(purpose: ReallyMeAndroidPlatformKeyPurpose): Byte =
    when (purpose) {
        ReallyMeAndroidPlatformKeyPurpose.SIGNING -> SIGNING_PURPOSE_CODE
        ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT -> KEY_AGREEMENT_PURPOSE_CODE
    }

internal fun purposeFromCode(code: Byte): ReallyMeAndroidPlatformKeyPurpose =
    when (code) {
        SIGNING_PURPOSE_CODE -> ReallyMeAndroidPlatformKeyPurpose.SIGNING
        KEY_AGREEMENT_PURPOSE_CODE -> ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT
        else -> throw ReallyMeCryptoException.InvalidInput()
    }

internal fun securityLevelCode(level: ReallyMeAndroidPlatformKeySecurityLevel): Byte =
    when (level) {
        ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT -> 1
        ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX -> 2
    }

internal fun securityLevelFromCode(code: Byte): ReallyMeAndroidPlatformKeySecurityLevel =
    when (code) {
        1.toByte() -> ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT
        2.toByte() -> ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX
        else -> throw ReallyMeCryptoException.InvalidInput()
    }
