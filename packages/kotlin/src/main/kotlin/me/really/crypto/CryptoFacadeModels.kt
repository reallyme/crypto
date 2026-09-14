// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto

import java.security.MessageDigest

public class ReallyMeSignatureKeyPair(
    public val publicKey: ByteArray,
    public val secretKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeSignatureKeyPair &&
            publicKey.contentEquals(other.publicKey) &&
            MessageDigest.isEqual(secretKey, other.secretKey)

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + secretKey.size

    override fun toString(): String =
        "ReallyMeSignatureKeyPair(publicKeyLength=${publicKey.size}, secretKey=<redacted>)"
}

public class ReallyMeKemKeyPair(
    public val publicKey: ByteArray,
    public val secretKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeKemKeyPair &&
            publicKey.contentEquals(other.publicKey) &&
            MessageDigest.isEqual(secretKey, other.secretKey)

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + secretKey.size

    override fun toString(): String =
        "ReallyMeKemKeyPair(publicKeyLength=${publicKey.size}, secretKey=<redacted>)"
}

public class ReallyMeKeyAgreementKeyPair(
    public val publicKey: ByteArray,
    public val secretKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeKeyAgreementKeyPair &&
            publicKey.contentEquals(other.publicKey) &&
            MessageDigest.isEqual(secretKey, other.secretKey)

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + secretKey.size

    override fun toString(): String =
        "ReallyMeKeyAgreementKeyPair(publicKeyLength=${publicKey.size}, secretKey=<redacted>)"
}

public class ReallyMeKemEncapsulation(
    public val sharedSecret: ByteArray,
    public val ciphertext: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeKemEncapsulation &&
            MessageDigest.isEqual(sharedSecret, other.sharedSecret) &&
            ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * ciphertext.contentHashCode() + sharedSecret.size

    override fun toString(): String =
        "ReallyMeKemEncapsulation(sharedSecret=<redacted>, ciphertextLength=${ciphertext.size})"
}

public class ReallyMeHpkeSealedMessage(
    public val encapsulatedKey: ByteArray,
    public val ciphertext: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReallyMeHpkeSealedMessage &&
            encapsulatedKey.contentEquals(other.encapsulatedKey) &&
            ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * encapsulatedKey.contentHashCode() + ciphertext.contentHashCode()
}
