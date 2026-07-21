// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/** Purpose authorization embedded into an opaque Android platform-key handle. */
public enum class ReallyMeAndroidPlatformKeyPurpose {
    SIGNING,
    KEY_AGREEMENT,
}

/** Hardware security levels accepted by the Android platform-key API. */
public enum class ReallyMeAndroidPlatformKeySecurityLevel {
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
}

/**
 * Generation policy for a non-exportable Android Keystore P-256 private key.
 *
 * The attestation challenge is copied on ingress and never included in string
 * output. A zero-second authentication timeout means every private-key use
 * requires a fresh authorization.
 */
public class ReallyMeAndroidPlatformKeyPolicy(
    public val requestedSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel =
        ReallyMeAndroidPlatformKeySecurityLevel.TRUSTED_ENVIRONMENT,
    public val userAuthenticationRequired: Boolean = false,
    public val userAuthenticationTimeoutSeconds: Int = 0,
    public val allowBiometricStrong: Boolean = true,
    public val allowDeviceCredential: Boolean = true,
    public val invalidatedByBiometricEnrollment: Boolean = false,
    public val userConfirmationRequired: Boolean = false,
    public val unlockedDeviceRequired: Boolean = false,
    attestationChallenge: ByteArray? = null,
) {
    private val ownedAttestationChallenge: ByteArray? = attestationChallenge?.copyOf()

    public val attestationChallenge: ByteArray?
        get() = ownedAttestationChallenge?.copyOf()

    override fun toString(): String =
        "ReallyMeAndroidPlatformKeyPolicy(" +
            "requestedSecurityLevel=$requestedSecurityLevel, " +
            "userAuthenticationRequired=$userAuthenticationRequired, " +
            "userAuthenticationTimeoutSeconds=$userAuthenticationTimeoutSeconds, " +
            "allowBiometricStrong=$allowBiometricStrong, " +
            "allowDeviceCredential=$allowDeviceCredential, " +
            "invalidatedByBiometricEnrollment=$invalidatedByBiometricEnrollment, " +
            "userConfirmationRequired=$userConfirmationRequired, " +
            "unlockedDeviceRequired=$unlockedDeviceRequired, " +
            "attestationChallenge=<redacted>)"
}

/** Public material and an opaque reference to an Android Keystore private key. */
public class ReallyMeAndroidPlatformKeyPair(
    public val purpose: ReallyMeAndroidPlatformKeyPurpose,
    public val requestedSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
    public val actualSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
    publicKey: ByteArray,
    privateKeyHandle: ByteArray,
) {
    private val ownedPublicKey: ByteArray = publicKey.copyOf()
    private val ownedPrivateKeyHandle: ByteArray = privateKeyHandle.copyOf()

    public val publicKey: ByteArray
        get() = ownedPublicKey.copyOf()

    public val privateKeyHandle: ByteArray
        get() = ownedPrivateKeyHandle.copyOf()

    override fun toString(): String =
        "ReallyMeAndroidPlatformKeyPair(" +
            "purpose=$purpose, " +
            "requestedSecurityLevel=$requestedSecurityLevel, " +
            "actualSecurityLevel=$actualSecurityLevel, " +
            "publicKeyLength=${ownedPublicKey.size}, " +
            "privateKeyHandle=<redacted>)"
}

/** Attestation evidence returned without exposing the persistent key alias. */
public class ReallyMeAndroidPlatformKeyAttestation(
    public val actualSecurityLevel: ReallyMeAndroidPlatformKeySecurityLevel,
    certificateChain: List<ByteArray>,
) {
    private val ownedCertificateChain: List<ByteArray> = certificateChain.map { it.copyOf() }

    public val certificateChain: List<ByteArray>
        get() = ownedCertificateChain.map { it.copyOf() }

    override fun toString(): String =
        "ReallyMeAndroidPlatformKeyAttestation(" +
            "actualSecurityLevel=$actualSecurityLevel, " +
            "certificateCount=${ownedCertificateChain.size}, " +
            "certificateChain=<redacted>)"
}
