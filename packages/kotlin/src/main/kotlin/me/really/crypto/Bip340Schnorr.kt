// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import fr.acinq.secp256k1.Secp256k1
import fr.acinq.secp256k1.Secp256k1Exception

/**
 * BIP-340 Schnorr signatures over secp256k1, backed by Bitcoin Core
 * libsecp256k1 (the constant-time reference implementation) via ACINQ's JNI
 * bindings — the same C library the Swift lane uses through CSecp256k1. No EC
 * scalar math is hand-rolled on the JVM, so there is no secret-dependent
 * timing surface, and signatures are byte-identical to every other lane.
 *
 * The generic `ReallyMeCrypto.sign` facade does not route here because BIP-340
 * signing requires caller-controlled 32-byte auxiliary randomness. Callers use
 * this object directly when they need signing, and the generic facade exposes
 * key generation plus verification.
 */
public object ReallyMeBip340Schnorr {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val PUBLIC_KEY_LENGTH: Int = 32
    public const val MESSAGE_LENGTH: Int = 32
    public const val AUX_RAND_LENGTH: Int = 32
    public const val SIGNATURE_LENGTH: Int = 64

    public fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val secp = provider()
        return withRandomSecretCandidate(
            length = SECRET_KEY_LENGTH,
            isValid = secp::secKeyVerify,
        ) { secretKey ->
            Pair(derivePublicKey(secretKey), secretKey.copyOf())
        }
    }

    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    /** Derives the 32-byte x-only BIP-340 public key for a 32-byte secret. */
    public fun derivePublicKey(secretKey: ByteArray): ByteArray {
        val secp = provider()
        validateSecretKey(secp, secretKey)
        return try {
            xOnly(secp, secp.pubkeyCreate(secretKey))
        } catch (_: Secp256k1Exception) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    public fun sign(message32: ByteArray, secretKey: ByteArray, auxRand32: ByteArray): ByteArray {
        if (message32.size != MESSAGE_LENGTH || auxRand32.size != AUX_RAND_LENGTH) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val secp = provider()
        validateSecretKey(secp, secretKey)
        return try {
            secp.signSchnorr(message32, secretKey, auxRand32)
        } catch (_: Secp256k1Exception) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
    }

    public fun verify(signature: ByteArray, message32: ByteArray, publicKey: ByteArray) {
        if (
            signature.size != SIGNATURE_LENGTH ||
            message32.size != MESSAGE_LENGTH ||
            publicKey.size != PUBLIC_KEY_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val secp = provider()
        val valid = try {
            secp.verifySchnorr(signature, message32, publicKey)
        } catch (_: Secp256k1Exception) {
            throw ReallyMeCryptoException.InvalidSignature()
        }
        if (!valid) {
            throw ReallyMeCryptoException.InvalidSignature()
        }
    }

    private fun provider(): Secp256k1 =
        try {
            Secp256k1.get()
        } catch (_: LinkageError) {
            throw ReallyMeCryptoException.ProviderFailure()
        } catch (_: RuntimeException) {
            throw ReallyMeCryptoException.ProviderFailure()
        }

    private fun validateSecretKey(secp: Secp256k1, secretKey: ByteArray) {
        if (secretKey.size != SECRET_KEY_LENGTH || !secp.secKeyVerify(secretKey)) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    /** x-only public key = the X coordinate of the SEC1 compressed public key. */
    private fun xOnly(secp: Secp256k1, uncompressedPublicKey: ByteArray): ByteArray =
        secp.pubKeyCompress(uncompressedPublicKey).copyOfRange(1, 1 + PUBLIC_KEY_LENGTH)
}
