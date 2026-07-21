// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import android.util.Base64
import android.os.Build
import android.content.pm.PackageManager
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ReallyMeCryptoAndroidInstrumentedTest {
    @Test
    fun aesGcmRoundTripsOnAndroidProviderLane() {
        val key = ByteArray(ReallyMeAesGcm.KEY_LENGTH) { index -> index.toByte() }
        val nonce = ByteArray(ReallyMeAesGcm.NONCE_LENGTH) { index -> (index + 16).toByte() }
        val aad = "reallyme-android-aead".toByteArray(Charsets.UTF_8)
        val plaintext = "android runtime provider smoke".toByteArray(Charsets.UTF_8)
        val cipher = ReallyMeJceProviders.bouncyCastleCipher("AES/GCM/NoPadding")

        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(cipher.provider))
        val sealed = ReallyMeCrypto.seal(
            ReallyMeAeadAlgorithm.AES_256_GCM,
            key,
            nonce,
            aad,
            plaintext,
        )
        val opened = ReallyMeCrypto.open(
            ReallyMeAeadAlgorithm.AES_256_GCM,
            key,
            nonce,
            aad,
            sealed,
        )

        assertArrayEquals(plaintext, opened)
    }

    @Test
    fun aesKwUsesBundledBouncyCastleProviderOnAndroid() {
        val wrappingKey = ByteArray(ReallyMeAesKw.WRAPPING_KEY_LENGTH) { index -> (index + 1).toByte() }
        val keyToWrap = ByteArray(ReallyMeAesKw.MIN_KEY_DATA_LENGTH) { index -> (index + 33).toByte() }
        val cipher = ReallyMeJceProviders.bouncyCastleCipher("AESWrap")

        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(cipher.provider))
        val wrapped = ReallyMeCrypto.wrapKey(
            ReallyMeKeyWrapAlgorithm.AES_256_KW,
            wrappingKey,
            keyToWrap,
        )
        assertEquals(keyToWrap.size + ReallyMeAesKw.INTEGRITY_LENGTH, wrapped.size)
        val unwrapped = ReallyMeCrypto.unwrapKey(
            ReallyMeKeyWrapAlgorithm.AES_256_KW,
            wrappingKey,
            wrapped,
        )

        assertEquals(wrapped.size - ReallyMeAesKw.INTEGRITY_LENGTH, unwrapped.size)
        assertArrayEquals(keyToWrap, unwrapped)
    }

    @Test
    fun rsaPkcs1v15AndPssVerifyOnAndroid() {
        val signature = ReallyMeJceProviders.bouncyCastleSignature("RSASSA-PSS")
        val keyFactory = ReallyMeJceProviders.bouncyCastleKeyFactory("RSA")
        val publicKeyDer = base64UrlBytes(
            "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4" +
                "CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJt" +
                "VqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkh" +
                "J88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9" +
                "lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB",
        )
        val message = base64UrlBytes("UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg")
        val pkcs1v15Sha256Signature = base64UrlBytes(
            "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0" +
                "V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_" +
                "MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67" +
                "xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_" +
                "Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw",
        )
        val pssSha256Signature = base64UrlBytes(
            "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_" +
                "FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4" +
                "IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEz" +
                "NPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWT" +
                "aJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw",
        )

        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(signature.provider))
        assertTrue(ReallyMeJceProviders.isBundledBouncyCastleProvider(keyFactory.provider))
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256,
            pkcs1v15Sha256Signature,
            message,
            publicKeyDer,
            ReallyMeRsaPublicKeyDerEncoding.PKCS1,
        )
        ReallyMeCrypto.verify(
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256,
            pssSha256Signature,
            message,
            publicKeyDer,
            ReallyMeRsaPublicKeyDerEncoding.PKCS1,
        )
    }

    @Test
    fun rustJniArgon2idRouteLoadsFromBundledAndroidLibrary() {
        assertEquals(ReallyMeNativeStatus.OK, ReallyMeRustNativeProvider.loadBundledLibraryStatus())
        val derived = ReallyMeArgon2id.deriveKey(
            ReallyMeArgon2id.V1,
            "android-rust-jni-secret".toByteArray(Charsets.UTF_8),
            "reallyme-argon2id-salt".toByteArray(Charsets.UTF_8),
        )

        assertEquals(ReallyMeArgon2id.DERIVED_KEY_LENGTH, derived.size)
    }

    @Test
    fun bip340SchnorrSignsAndVerifiesOnAndroidSecp256k1Lane() {
        val secretKey = ByteArray(ReallyMeBip340Schnorr.SECRET_KEY_LENGTH) { index -> (index + 1).toByte() }
        val publicKey = ReallyMeBip340Schnorr.derivePublicKey(secretKey)
        val message = ByteArray(ReallyMeBip340Schnorr.MESSAGE_LENGTH) { index -> (index + 64).toByte() }
        val auxRand = ByteArray(ReallyMeBip340Schnorr.AUX_RAND_LENGTH) { index -> (index + 96).toByte() }
        val signature = ReallyMeCrypto.signBip340Schnorr(message, secretKey, auxRand)

        assertEquals(ReallyMeBip340Schnorr.PUBLIC_KEY_LENGTH, publicKey.size)
        assertEquals(ReallyMeBip340Schnorr.SIGNATURE_LENGTH, signature.size)
        ReallyMeCrypto.verify(ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256, signature, message, publicKey)
    }

    @Test
    fun p256AndroidKeystoreSigningIsHardwareBackedOrFailsClosed() {
        if (Build.VERSION.SDK_INT < 31) {
            assertTypedFailure<ReallyMeCryptoException.UnsupportedPlatform> {
                ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                    applicationTag = "unsupported-signing".toByteArray(Charsets.UTF_8),
                )
            }
            return
        }

        val applicationTag = "me.really.crypto.android.signing.${UUID.randomUUID()}"
            .toByteArray(Charsets.UTF_8)
        val attestationChallenge = ByteArray(32) { index -> (index + 1).toByte() }
        val policy = ReallyMeAndroidPlatformKeyPolicy(
            requestedSecurityLevel = ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT,
            attestationChallenge = attestationChallenge,
        )
        val keyPair = try {
            ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                applicationTag = applicationTag,
                policy = policy,
                overwriteExisting = true,
            )
        } catch (_: ReallyMeCryptoException.HardwareUnavailable) {
            assertTrue("physical devices must provide hardware-backed Android Keystore", isEmulator())
            assertHardwareGenerationFailsClosedWithoutLeavingDuplicate {
                ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                    applicationTag = applicationTag,
                    policy = policy,
                    overwriteExisting = false,
                )
            }
            attestationChallenge.fill(0)
            applicationTag.fill(0)
            return
        }

        try {
            assertEquals(ReallyMeAndroidPlatformKeyPurpose.SIGNING, keyPair.purpose)
            assertEquals(
                keyPair.actualSecurityLevel,
                ReallyMeAndroidPlatformKeys.actualSecurityLevel(keyPair.privateKeyHandle),
            )
            assertArrayEquals(
                keyPair.publicKey,
                ReallyMeAndroidPlatformKeys.getPublicKey(keyPair.privateKeyHandle),
            )
            assertFalse(keyPair.toString().contains(keyPair.privateKeyHandle.contentToString()))
            assertFalse(keyPair.privateKeyHandle.containsSubsequence(applicationTag))

            val message = "ReallyMe Android hardware signing test".toByteArray(Charsets.UTF_8)
            val signature = ReallyMeAndroidPlatformKeys.sign(message, keyPair.privateKeyHandle)
            assertEquals(0x30.toByte(), signature.first())
            ReallyMeAndroidPlatformKeys.verify(signature, message, keyPair.publicKey)

            val attestation = ReallyMeAndroidPlatformKeys.attest(keyPair.privateKeyHandle)
            assertEquals(keyPair.actualSecurityLevel, attestation.actualSecurityLevel)
            assertTrue(attestation.certificateChain.isNotEmpty())
            assertFalse(attestation.toString().contains("certificateChain=[["))
            assertAttestationEvidence(
                attestation = attestation,
                expectedChallenge = attestationChallenge,
                expectedSecurityLevel = keyPair.actualSecurityLevel,
            )

            assertTypedFailure<ReallyMeCryptoException.PlatformKeyAlreadyExists> {
                ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                    applicationTag = applicationTag,
                    policy = policy,
                    overwriteExisting = false,
                )
            }
            assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
                ReallyMeAndroidPlatformKeys.newKeyAgreementOperation(keyPair.privateKeyHandle)
            }
        } finally {
            ReallyMeAndroidPlatformKeys.deleteKey(keyPair.privateKeyHandle)
            attestationChallenge.fill(0)
            applicationTag.fill(0)
        }

        assertTypedFailure<ReallyMeCryptoException.PlatformKeyNotFound> {
            ReallyMeAndroidPlatformKeys.getPublicKey(keyPair.privateKeyHandle)
        }
        ReallyMeAndroidPlatformKeys.deleteKey(keyPair.privateKeyHandle)
    }

    @Test
    fun p256AndroidKeystoreEcdhIsHardwareBackedOrFailsClosed() {
        if (Build.VERSION.SDK_INT < 31) {
            assertTypedFailure<ReallyMeCryptoException.UnsupportedPlatform> {
                ReallyMeAndroidPlatformKeys.generateKeyAgreementKeyPair(
                    applicationTag = "unsupported-ecdh".toByteArray(Charsets.UTF_8),
                )
            }
            return
        }

        val applicationTag = "me.really.crypto.android.ecdh.${UUID.randomUUID()}"
            .toByteArray(Charsets.UTF_8)
        val policy = ReallyMeAndroidPlatformKeyPolicy(
            requestedSecurityLevel = ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT,
        )
        val keyPair = try {
            ReallyMeAndroidPlatformKeys.generateKeyAgreementKeyPair(
                applicationTag = applicationTag,
                policy = policy,
                overwriteExisting = true,
            )
        } catch (_: ReallyMeCryptoException.HardwareUnavailable) {
            assertTrue("physical devices must provide hardware-backed Android Keystore", isEmulator())
            assertHardwareGenerationFailsClosedWithoutLeavingDuplicate {
                ReallyMeAndroidPlatformKeys.generateKeyAgreementKeyPair(
                    applicationTag = applicationTag,
                    policy = policy,
                    overwriteExisting = false,
                )
            }
            applicationTag.fill(0)
            return
        }

        val peer = ReallyMeP256Ecdh.generateKeyPair()
        var platformSecret = ByteArray(0)
        var peerSecret = ByteArray(0)
        try {
            platformSecret = ReallyMeAndroidPlatformKeys.deriveSharedSecret(
                peerPublicKey = peer.first,
                privateKeyHandle = keyPair.privateKeyHandle,
            )
            peerSecret = ReallyMeP256Ecdh.deriveSharedSecret(keyPair.publicKey, peer.second)
            assertEquals(ReallyMeAndroidPlatformKeyPurpose.KEY_AGREEMENT, keyPair.purpose)
            assertEquals(ReallyMeAndroidPlatformKeys.SHARED_SECRET_LENGTH, platformSecret.size)
            assertArrayEquals(peerSecret, platformSecret)
            assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
                ReallyMeAndroidPlatformKeys.deriveSharedSecret(
                    peerPublicKey =
                        ByteArray(ReallyMeAndroidPlatformKeys.COMPRESSED_PUBLIC_KEY_LENGTH),
                    privateKeyHandle = keyPair.privateKeyHandle,
                )
            }
            assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
                ReallyMeAndroidPlatformKeys.newSigningOperation(keyPair.privateKeyHandle)
            }
        } finally {
            platformSecret.fill(0)
            peerSecret.fill(0)
            peer.second.fill(0)
            ReallyMeAndroidPlatformKeys.deleteKey(keyPair.privateKeyHandle)
            applicationTag.fill(0)
        }
    }

    @Test
    fun p256AndroidStrongBoxSigningWhenAdvertised() {
        assumeTrue(Build.VERSION.SDK_INT >= 31)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
        )
        val applicationTag = "me.really.crypto.android.strongbox.${UUID.randomUUID()}"
            .toByteArray(Charsets.UTF_8)
        val attestationChallenge = ByteArray(32) { index -> (index + 33).toByte() }
        val keyPair = ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
            applicationTag = applicationTag,
            policy = ReallyMeAndroidPlatformKeyPolicy(
                requestedSecurityLevel = ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX,
                attestationChallenge = attestationChallenge,
            ),
            overwriteExisting = true,
        )
        try {
            assertEquals(
                ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX,
                keyPair.actualSecurityLevel,
            )
            val message = "ReallyMe Android StrongBox signing test".toByteArray(Charsets.UTF_8)
            val signature = ReallyMeAndroidPlatformKeys.sign(message, keyPair.privateKeyHandle)
            ReallyMeAndroidPlatformKeys.verify(signature, message, keyPair.publicKey)
            assertAttestationEvidence(
                attestation = ReallyMeAndroidPlatformKeys.attest(keyPair.privateKeyHandle),
                expectedChallenge = attestationChallenge,
                expectedSecurityLevel = ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX,
            )
        } finally {
            ReallyMeAndroidPlatformKeys.deleteKey(keyPair.privateKeyHandle)
            attestationChallenge.fill(0)
            applicationTag.fill(0)
        }
    }

    @Test
    fun androidPlatformKeyBoundaryValidationIsTyped() {
        assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
            ReallyMeAndroidPlatformKeys.generateSigningKeyPair(ByteArray(0))
        }
        assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
            ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                ByteArray(ReallyMeAndroidPlatformKeys.MAX_APPLICATION_TAG_LENGTH + 1),
            )
        }
        assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
            ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                "oversized-attestation".toByteArray(Charsets.UTF_8),
                ReallyMeAndroidPlatformKeyPolicy(
                    attestationChallenge =
                        ByteArray(ReallyMeAndroidPlatformKeys.MAX_ATTESTATION_CHALLENGE_LENGTH + 1),
                ),
            )
        }
        assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
            ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                "short-attestation".toByteArray(Charsets.UTF_8),
                ReallyMeAndroidPlatformKeyPolicy(
                    attestationChallenge =
                        ByteArray(ReallyMeAndroidPlatformKeys.MIN_ATTESTATION_CHALLENGE_LENGTH - 1),
                ),
            )
        }
        assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
            ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                "invalid-auth-policy".toByteArray(Charsets.UTF_8),
                ReallyMeAndroidPlatformKeyPolicy(
                    userAuthenticationRequired = true,
                    allowBiometricStrong = false,
                    allowDeviceCredential = false,
                ),
            )
        }
        if (Build.VERSION.SDK_INT < 31) {
            assertTypedFailure<ReallyMeCryptoException.UnsupportedPlatform> {
                ReallyMeAndroidPlatformKeys.getPublicKey(ByteArray(39))
            }
        } else {
            assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
                ReallyMeAndroidPlatformKeys.getPublicKey(ByteArray(39))
            }
        }
        assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
            ReallyMeAndroidPlatformKeys.generateSigningKeyPair(
                "unenforceable-enrollment-policy".toByteArray(Charsets.UTF_8),
                ReallyMeAndroidPlatformKeyPolicy(
                    userAuthenticationRequired = true,
                    allowBiometricStrong = true,
                    allowDeviceCredential = true,
                    invalidatedByBiometricEnrollment = true,
                ),
            )
        }
        assertTypedFailure<ReallyMeCryptoException.InvalidInput> {
            ReallyMeAndroidPlatformKeys.generateKeyAgreementKeyPair(
                "confirmation-is-signing-only".toByteArray(Charsets.UTF_8),
                ReallyMeAndroidPlatformKeyPolicy(userConfirmationRequired = true),
            )
        }
    }

    private fun assertAttestationEvidence(
        attestation: ReallyMeAndroidPlatformKeyAttestation,
        expectedChallenge: ByteArray,
        expectedSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
    ) {
        val factory = CertificateFactory.getInstance("X.509")
        val certificates = attestation.certificateChain.map { encoded ->
            factory.generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
        }
        for (index in 0 until certificates.lastIndex) {
            certificates[index].verify(certificates[index + 1].publicKey)
        }

        val extension = certificates.first().getExtensionValue(KEY_ATTESTATION_EXTENSION_OID)
        assertTrue("leaf certificate must carry Android key attestation", extension != null)
        if (extension == null) {
            return
        }
        val wrappedDescription = ASN1OctetString.getInstance(extension)
        val description = ASN1Sequence.getInstance(wrappedDescription.octets)
        val securityLevel = ASN1Enumerated.getInstance(description.getObjectAt(1)).value.toInt()
        val challenge = ASN1OctetString.getInstance(description.getObjectAt(4)).octets
        try {
            assertArrayEquals(expectedChallenge, challenge)
            assertEquals(attestationSecurityLevelCode(expectedSecurityLevel), securityLevel)
        } finally {
            challenge.fill(0)
        }
    }

    private fun attestationSecurityLevelCode(
        level: ReallyMeAndroidPlatformKeySecurityLevel,
    ): Int =
        when (level) {
            ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT -> 1
            ReallyMeAndroidPlatformKeySecurityLevel.STRONGBOX -> 2
        }

    private fun assertHardwareGenerationFailsClosedWithoutLeavingDuplicate(
        generate: () -> ReallyMeAndroidPlatformKeyPair,
    ) {
        assertTypedFailure<ReallyMeCryptoException.HardwareUnavailable> {
            generate()
        }
    }

    private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean {
        if (candidate.isEmpty() || candidate.size > size) {
            return false
        }
        return (0..size - candidate.size).any { offset ->
            candidate.indices.all { index -> this[offset + index] == candidate[index] }
        }
    }

    private inline fun <reified T : Throwable> assertTypedFailure(block: () -> Unit) {
        try {
            block()
            fail("expected typed failure ${T::class.java.simpleName}")
        } catch (error: Throwable) {
            assertTrue("expected ${T::class.java.simpleName}, got ${error.javaClass.simpleName}", error is T)
        }
    }

    private fun isEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.contains("emulator") ||
            Build.FINGERPRINT.contains("/emu") ||
            Build.HARDWARE.contains("ranchu") ||
            Build.HARDWARE.contains("goldfish") ||
            Build.PRODUCT.startsWith("sdk_") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for")

    private fun base64UrlBytes(encoded: String): ByteArray =
        Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private companion object {
        const val KEY_ATTESTATION_EXTENSION_OID: String = "1.3.6.1.4.1.11129.2.1.17"
    }
}
