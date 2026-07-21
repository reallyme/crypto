// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
 * Non-exportable P-256 signing and ECDH keys held by Android Keystore.
 *
 * Public callers identify keys with bounded application-tag bytes. The raw tag
 * is domain-separated and hashed before it becomes a Keystore alias, and the
 * returned binary handle contains only the purpose and digest. Every private
 * operation revalidates the handle purpose and the key's hardware residency;
 * raw-key facade methods are never used as a fallback.
 */
public object ReallyMeAndroidPlatformKeys {
    public const val MIN_APPLICATION_TAG_LENGTH: Int = 1
    public const val MAX_APPLICATION_TAG_LENGTH: Int = 256
    public const val MIN_ATTESTATION_CHALLENGE_LENGTH: Int = 16
    public const val MAX_ATTESTATION_CHALLENGE_LENGTH: Int = 128
    public const val MAX_AUTHENTICATION_TIMEOUT_SECONDS: Int = 86_400
    public const val COMPRESSED_PUBLIC_KEY_LENGTH: Int = 33
    public const val SHARED_SECRET_LENGTH: Int = 32
    public const val SIGNATURE_DER_MAX_LENGTH: Int = 72

    private const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
    private const val ANDROID_OPENSSL: String = "AndroidOpenSSL"
    private const val EC_ALGORITHM: String = "EC"
    private const val P256_CURVE: String = "secp256r1"
    private const val ECDH_ALGORITHM: String = "ECDH"
    private const val ECDSA_SHA256_ALGORITHM: String = "SHA256withECDSA"
    private const val HANDLE_VERSION: Byte = 1
    private const val HANDLE_LENGTH: Int = 39
    private const val HANDLE_SECURITY_LEVEL_OFFSET: Int = 6
    private const val HANDLE_DIGEST_OFFSET: Int = 7
    private const val DIGEST_LENGTH: Int = 32
    private const val SIGNING_PURPOSE_CODE: Byte = 1
    private const val KEY_AGREEMENT_PURPOSE_CODE: Byte = 2
    private const val STRONGBOX_UNAVAILABLE_EXCEPTION: String =
        "android.security.keystore.StrongBoxUnavailableException"
    private const val ALIAS_PREFIX: String = "me.really.crypto.platform-key.v1"
    private val handleMagic: ByteArray = byteArrayOf(0x52, 0x4d, 0x41, 0x4b)
    private val aliasDomain: ByteArray =
        "me.really.crypto.android-platform-key.v1".toByteArray(Charsets.US_ASCII)

    public fun generateSigningKeyPair(
        applicationTag: ByteArray,
        policy: ReallyMeAndroidPlatformKeyPolicy = ReallyMeAndroidPlatformKeyPolicy(),
        overwriteExisting: Boolean = false,
    ): ReallyMeAndroidPlatformKeyPair =
        generateKeyPair(
            purpose = ReallyMeAndroidPlatformKeyPurpose.SIGNING,
            applicationTag = applicationTag,
            policy = policy,
            overwriteExisting = overwriteExisting,
        )

    public fun generateKeyAgreementKeyPair(
        applicationTag: ByteArray,
        policy: ReallyMeAndroidPlatformKeyPolicy = ReallyMeAndroidPlatformKeyPolicy(),
        overwriteExisting: Boolean = false,
    ): ReallyMeAndroidPlatformKeyPair =
        generateKeyPair(
            purpose = ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT,
            applicationTag = applicationTag,
            policy = policy,
            overwriteExisting = overwriteExisting,
        )

    public fun getPublicKey(privateKeyHandle: ByteArray): ByteArray {
        requirePlatformKeyApi()
        val resolved = resolveHandle(privateKeyHandle)
        return withMappedPlatformErrors {
            val entry = privateKeyEntry(resolved.alias)
            validatePrivateKey(
                entry.privateKey,
                resolved.purpose,
                resolved.actualSecurityLevel,
            )
            compressedPublicKey(entry.certificate.publicKey)
        }
    }

    public fun actualSecurityLevel(
        privateKeyHandle: ByteArray,
    ): ReallyMeAndroidPlatformKeySecurityLevel {
        requirePlatformKeyApi()
        val resolved = resolveHandle(privateKeyHandle)
        return withMappedPlatformErrors {
            val entry = privateKeyEntry(resolved.alias)
            inspectPrivateKey(
                entry.privateKey,
                resolved.purpose,
                resolved.actualSecurityLevel,
            )
        }
    }

    public fun sign(message: ByteArray, privateKeyHandle: ByteArray): ByteArray {
        val signature = newSigningOperation(privateKeyHandle)
        return withMappedPlatformErrors {
            signature.update(message)
            val encoded = signature.sign()
            if (encoded.isEmpty() || encoded.size > SIGNATURE_DER_MAX_LENGTH) {
                encoded.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            encoded
        }
    }

    /**
     * Creates an initialized signing primitive for direct use or wrapping in a
     * biometric prompt's CryptoObject. No prompt or activity is retained here.
     */
    public fun newSigningOperation(privateKeyHandle: ByteArray): Signature {
        requirePlatformKeyApi()
        val resolved = resolveHandle(privateKeyHandle, ReallyMeAndroidPlatformKeyPurpose.SIGNING)
        return withMappedPlatformErrors {
            val privateKey = privateKeyEntry(resolved.alias).privateKey
            validatePrivateKey(
                privateKey,
                ReallyMeAndroidPlatformKeyPurpose.SIGNING,
                resolved.actualSecurityLevel,
            )
            Signature.getInstance(ECDSA_SHA256_ALGORITHM).apply {
                initSign(privateKey)
            }
        }
    }

    public fun verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray) {
        ReallyMeP256Ecdsa.verify(signature, message, publicKey)
    }

    public fun deriveSharedSecret(
        peerPublicKey: ByteArray,
        privateKeyHandle: ByteArray,
    ): ByteArray {
        val agreement = newKeyAgreementOperation(privateKeyHandle)
        val peer = decodeCompressedPublicKey(peerPublicKey)
        return withMappedPlatformErrors {
            agreement.doPhase(peer, true)
            val secret = agreement.generateSecret()
            if (secret.size != SHARED_SECRET_LENGTH) {
                secret.fill(0)
                throw ReallyMeCryptoException.ProviderFailure()
            }
            secret
        }
    }

    /**
     * Creates an initialized ECDH primitive suitable for a biometric prompt's
     * CryptoObject.
     *
     * Prefer [deriveSharedSecret] outside that prompt flow. This low-level JCA
     * object cannot enforce the SDK's compressed peer-key validation once it is
     * returned to the caller.
     */
    public fun newKeyAgreementOperation(privateKeyHandle: ByteArray): KeyAgreement {
        requirePlatformKeyApi()
        val resolved = resolveHandle(
            privateKeyHandle,
            ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT,
        )
        return withMappedPlatformErrors {
            val privateKey = privateKeyEntry(resolved.alias).privateKey
            validatePrivateKey(
                privateKey,
                ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT,
                resolved.actualSecurityLevel,
            )
            KeyAgreement.getInstance(ECDH_ALGORITHM, ANDROID_KEYSTORE).apply {
                init(privateKey)
            }
        }
    }

    @Synchronized
    public fun deleteKey(privateKeyHandle: ByteArray) {
        requirePlatformKeyApi()
        val resolved = resolveHandle(privateKeyHandle)
        withMappedPlatformErrors {
            val store = loadKeyStore()
            if (store.containsAlias(resolved.alias)) {
                store.deleteEntry(resolved.alias)
            }
        }
    }

    /**
     * Returns the provider certificate chain created with the generation-time
     * attestation challenge. Callers must validate the chain, challenge, root,
     * revocation state, and authorization extension in their trust domain.
     */
    public fun attest(privateKeyHandle: ByteArray): ReallyMeAndroidPlatformKeyAttestation {
        requirePlatformKeyApi()
        val resolved = resolveHandle(privateKeyHandle)
        return withMappedPlatformErrors {
            val store = loadKeyStore()
            val entry = privateKeyEntry(store, resolved.alias)
            val actualSecurityLevel = inspectPrivateKey(
                entry.privateKey,
                resolved.purpose,
                resolved.actualSecurityLevel,
            )
            val chain = store.getCertificateChain(resolved.alias)
                ?.map { certificate -> certificate.encoded }
                ?.takeIf { certificates -> certificates.isNotEmpty() }
                ?: throw ReallyMeCryptoException.ProviderFailure()
            ReallyMeAndroidPlatformKeyAttestation(actualSecurityLevel, chain)
        }
    }

    @Synchronized
    private fun generateKeyPair(
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
    private fun generationSpec(
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

    private fun validatePolicy(
        policy: ReallyMeAndroidPlatformKeyPolicy,
        purpose: ReallyMeAndroidPlatformKeyPurpose,
    ) {
        if (policy.userAuthenticationTimeoutSeconds !in 0..MAX_AUTHENTICATION_TIMEOUT_SECONDS) {
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
            challenge.size !in MIN_ATTESTATION_CHALLENGE_LENGTH..MAX_ATTESTATION_CHALLENGE_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun validateApplicationTag(applicationTag: ByteArray) {
        if (applicationTag.size !in MIN_APPLICATION_TAG_LENGTH..MAX_APPLICATION_TAG_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun requirePlatformKeyApi() {
        if (Build.VERSION.SDK_INT < 31) {
            throw ReallyMeCryptoException.UnsupportedPlatform()
        }
    }

    @TargetApi(31)
    private fun keyPurpose(purpose: ReallyMeAndroidPlatformKeyPurpose): Int =
        when (purpose) {
            ReallyMeAndroidPlatformKeyPurpose.SIGNING -> KeyProperties.PURPOSE_SIGN
            ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT -> KeyProperties.PURPOSE_AGREE_KEY
        }

    @TargetApi(31)
    private fun configureUserAuthentication(
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

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun privateKeyEntry(alias: String): KeyStore.PrivateKeyEntry =
        privateKeyEntry(loadKeyStore(), alias)

    private fun privateKeyEntry(store: KeyStore, alias: String): KeyStore.PrivateKeyEntry {
        if (!store.containsAlias(alias)) {
            throw ReallyMeCryptoException.PlatformKeyNotFound()
        }
        return store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw ReallyMeCryptoException.HardwareRejectedKey()
    }

    private fun validatePrivateKey(
        privateKey: PrivateKey,
        purpose: ReallyMeAndroidPlatformKeyPurpose,
        expectedSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
    ) {
        inspectPrivateKey(privateKey, purpose, expectedSecurityLevel)
    }

    private fun inspectPrivateKey(
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
    private fun exactHardwareSecurityLevel(
        keyInfo: KeyInfo,
    ): ReallyMeAndroidPlatformKeySecurityLevel =
        when (keyInfo.securityLevel) {
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT
            KeyProperties.SECURITY_LEVEL_STRONGBOX ->
                ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX
            else -> throw ReallyMeCryptoException.HardwareUnavailable()
        }

    private fun enforceRequestedSecurityLevel(
        requested: ReallyMeAndroidPlatformKeySecurityLevel,
        actual: ReallyMeAndroidPlatformKeySecurityLevel,
    ) {
        if (requested == ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX &&
            actual != ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX
        ) {
            throw ReallyMeCryptoException.HardwareUnavailable()
        }
    }

    private fun compressedPublicKey(publicKey: java.security.PublicKey): ByteArray {
        val ecPublicKey = publicKey as? ECPublicKey
            ?: throw ReallyMeCryptoException.HardwareRejectedKey()
        val x = unsignedFixed(ecPublicKey.w.affineX, SHARED_SECRET_LENGTH)
        val prefix: Byte = if (ecPublicKey.w.affineY.testBit(0)) 0x03.toByte() else 0x02.toByte()
        return byteArrayOf(prefix) + x
    }

    private fun decodeCompressedPublicKey(publicKey: ByteArray): java.security.PublicKey {
        if (publicKey.size != COMPRESSED_PUBLIC_KEY_LENGTH) {
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

    private fun unsignedFixed(value: BigInteger, length: Int): ByteArray {
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

    private fun applicationTagDigest(
        applicationTag: ByteArray,
        purpose: ReallyMeAndroidPlatformKeyPurpose,
    ): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").run {
            update(aliasDomain)
            update(0.toByte())
            update(purposeCode(purpose))
            digest(applicationTag)
        }

    private fun encodeHandle(
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

    private fun resolveHandle(
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

    private fun aliasFor(
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

    private fun purposeCode(purpose: ReallyMeAndroidPlatformKeyPurpose): Byte =
        when (purpose) {
            ReallyMeAndroidPlatformKeyPurpose.SIGNING -> SIGNING_PURPOSE_CODE
            ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT -> KEY_AGREEMENT_PURPOSE_CODE
        }

    private fun purposeFromCode(code: Byte): ReallyMeAndroidPlatformKeyPurpose =
        when (code) {
            SIGNING_PURPOSE_CODE -> ReallyMeAndroidPlatformKeyPurpose.SIGNING
            KEY_AGREEMENT_PURPOSE_CODE -> ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT
            else -> throw ReallyMeCryptoException.InvalidInput()
        }

    private fun securityLevelCode(level: ReallyMeAndroidPlatformKeySecurityLevel): Byte =
        when (level) {
            ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT -> 1
            ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX -> 2
        }

    private fun securityLevelFromCode(code: Byte): ReallyMeAndroidPlatformKeySecurityLevel =
        when (code) {
            1.toByte() -> ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT
            2.toByte() -> ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX
            else -> throw ReallyMeCryptoException.InvalidInput()
        }

    private fun bestEffortDelete(alias: String) {
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

    private fun mapPlatformError(error: Throwable): ReallyMeCryptoException =
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

    private inline fun <T> withMappedPlatformErrors(operation: () -> T): T =
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

    private class ResolvedHandle(
        val alias: String,
        val purpose: ReallyMeAndroidPlatformKeyPurpose,
        val actualSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
    )
}
