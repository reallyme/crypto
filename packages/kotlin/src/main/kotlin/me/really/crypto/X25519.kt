// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

/**
 * X25519 key agreement backed by BouncyCastle.
 *
 * The package returns the raw 32-byte Diffie-Hellman output. Higher-level
 * protocols must bind it through their own KDF transcript; this primitive does
 * not apply HKDF implicitly because HPKE, MLS, and ratchets label transcripts
 * differently.
 */
public object ReallyMeX25519 {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val PUBLIC_KEY_LENGTH: Int = 32
    public const val SHARED_SECRET_LENGTH: Int = 32

    /** Generates a random X25519 keypair: 32-byte public key, 32-byte secret. */
    public fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val secretKey = ByteArray(SECRET_KEY_LENGTH)
        SecureRandom().nextBytes(secretKey)
        return Pair(derivePublicKey(secretKey), secretKey)
    }

    /** Derives an X25519 keypair from a 32-byte secret. */
    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    /** Derives the 32-byte X25519 public key from a 32-byte secret. */
    public fun derivePublicKey(secretKey: ByteArray): ByteArray {
        if (secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return X25519PrivateKeyParameters(secretKey, 0).generatePublicKey().encoded
    }

    /** Derives the raw 32-byte X25519 shared secret. */
    public fun deriveSharedSecret(publicKey: ByteArray, secretKey: ByteArray): ByteArray {
        if (publicKey.size != PUBLIC_KEY_LENGTH || secretKey.size != SECRET_KEY_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        val sharedSecret = ByteArray(SHARED_SECRET_LENGTH)
        try {
            X25519PrivateKeyParameters(secretKey, 0).generateSecret(
                X25519PublicKeyParameters(publicKey, 0),
                sharedSecret,
                0,
            )
        } catch (_: IllegalArgumentException) {
            throw ReallyMeCryptoException.InvalidInput()
        } catch (_: IllegalStateException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

        if (sharedSecret.all { it == 0.toByte() }) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return sharedSecret
    }
}
