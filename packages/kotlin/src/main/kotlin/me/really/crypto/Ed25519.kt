// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Ed25519 signatures backed by BouncyCastle.
 *
 * The workspace contract uses the plain Ed25519 variant: callers pass the full
 * message, the provider signs that message directly, and signatures are the
 * 64-byte RFC 8032 encoding. Ed25519 is deterministic, so the same key and
 * message must produce the same bytes in every platform lane.
 */
public object ReallyMeEd25519 {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val PUBLIC_KEY_LENGTH: Int = 32
    public const val SIGNATURE_LENGTH: Int = 64

    /** Generates a random Ed25519 keypair: 32-byte public key, 32-byte seed. */
    public fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val secretKey = ByteArray(SECRET_KEY_LENGTH)
        SecureRandom().nextBytes(secretKey)
        return Pair(derivePublicKey(secretKey), secretKey)
    }

    /** Derives an Ed25519 keypair from a 32-byte seed. */
    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    /** Derives the 32-byte Ed25519 public key from a 32-byte seed. */
    public fun derivePublicKey(secretKey: ByteArray): ByteArray {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return Ed25519PrivateKeyParameters(secretKey, 0).generatePublicKey().encoded
    }

    /** Signs the full message using plain deterministic Ed25519. */
    public fun sign(message: ByteArray, secretKey: ByteArray): ByteArray {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(secretKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /**
     * Verifies a 64-byte Ed25519 signature against a 32-byte public key.
     *
     * Throws on malformed input shape; returns false for well-formed
     * signatures that do not verify.
     */
    public fun verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray) {
        if (signature.size != SIGNATURE_LENGTH || publicKey.size != PUBLIC_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        if (!verifier.verifySignature(signature)) {
            throw ReallyMeCryptoException.InvalidSignature()
        }
    }
}
