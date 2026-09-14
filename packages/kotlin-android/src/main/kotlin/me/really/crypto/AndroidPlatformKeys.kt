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
        return completeKeyAgreementOperation(agreement, peerPublicKey)
    }

    /**
     * Completes one initialized, optionally biometric-authorized ECDH operation.
     *
     * Android requires the actual [KeyAgreement] object to cross the
     * `BiometricPrompt.CryptoObject` boundary. Completion returns here so peer
     * SEC1 validation, platform-key conversion, ECDH, and output bounds remain
     * owned by ReallyMe Crypto instead of being copied into each SDK.
     */
    public fun completeKeyAgreementOperation(
        agreement: KeyAgreement,
        peerPublicKey: ByteArray,
    ): ByteArray {
        val peer = decodeCompressedPublicKey(peerPublicKey)
        return withMappedPlatformErrors {
            agreement.doPhase(peer, true)
            val secret = agreement.generateSecret()
            if (secret.size != SHARED_SECRET_LENGTH || secret.all { value -> value == 0.toByte() }) {
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

}
