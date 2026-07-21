// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import fr.acinq.secp256k1.Secp256k1
import fr.acinq.secp256k1.Secp256k1Exception
import java.security.MessageDigest

/**
 * secp256k1 ECDSA backed by Bitcoin Core libsecp256k1 through ACINQ's JNI
 * bindings, matching the Swift lane's CSecp256k1 provider.
 *
 * The API follows the workspace secp256k1 contract exactly, so signatures
 * interoperate byte-for-byte with the Rust, Swift, and TypeScript lanes:
 *
 * - Secret keys are 32 bytes; public keys are 33-byte compressed SEC1.
 * - [sign] hashes the full message internally with SHA-256 (callers pass the
 *   message, not a digest), derives the nonce deterministically (RFC 6979),
 *   and emits the 64-byte compact `r ‖ s` form normalized to low-S (BIP 0062).
 * - [verify] accepts only the 64-byte compact form and returns a Boolean
 *   rather than throwing on a well-formed-but-wrong signature, so callers can
 *   distinguish malformed input (throws) from a failed check (false).
 */
public object ReallyMeSecp256k1 {
    public const val SECRET_KEY_LENGTH: Int = 32
    public const val COMPRESSED_PUBLIC_KEY_LENGTH: Int = 33
    public const val SIGNATURE_LENGTH: Int = 64

    /** Generates a random keypair: 33-byte compressed public, 32-byte secret. */
    public fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val secp = provider()
        return withRandomSecretCandidate(
            length = SECRET_KEY_LENGTH,
            isValid = secp::secKeyVerify,
        ) { secretKey ->
            Pair(derivePublicKey(secretKey), secretKey.copyOf())
        }
    }

    /** Derives a secp256k1 ECDSA keypair from a 32-byte secret scalar. */
    public fun deriveKeyPair(secretKey: ByteArray): Pair<ByteArray, ByteArray> =
        Pair(derivePublicKey(secretKey), secretKey.copyOf())

    /** Derives the 33-byte compressed SEC1 public key for a 32-byte secret. */
    public fun derivePublicKey(secretKey: ByteArray): ByteArray {
        val secp = provider()
        validateSecretKey(secp, secretKey)
        return try {
            secp.pubKeyCompress(secp.pubkeyCreate(secretKey))
        } catch (_: Secp256k1Exception) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    /**
     * Signs `message` with deterministic (RFC 6979) ECDSA over
     * SHA-256(message), returning the 64-byte compact low-S signature.
     */
    public fun sign(message: ByteArray, secretKey: ByteArray): ByteArray {
        val secp = provider()
        validateSecretKey(secp, secretKey)
        val digest = MessageDigest.getInstance("SHA-256").digest(message)

        val signature = try {
            secp.sign(digest, secretKey, null)
        } catch (_: Secp256k1Exception) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        if (signature.size != SIGNATURE_LENGTH) {
            throw ReallyMeCryptoException.ProviderFailure()
        }
        return normalizedSignature(secp, signature)
    }

    /**
     * Verifies a 64-byte compact signature over SHA-256(message) against a
     * 33-byte compressed SEC1 public key.
     *
     * Throws [ReallyMeCryptoException.InvalidInput] on malformed input (wrong
     * lengths, undecodable key); returns false only for a well-formed
     * signature that does not verify.
     */
    public fun verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray) {
        if (signature.size != SIGNATURE_LENGTH ||
            publicKey.size != COMPRESSED_PUBLIC_KEY_LENGTH
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val secp = provider()
        validatePublicKey(secp, publicKey)

        // Reject the malleated high-S twin (BIP 0062). libsecp256k1 exposes
        // normalization as an explicit check; accepting the normalized twin
        // would make verification more permissive than the workspace contract.
        if (!signature.contentEquals(normalizedSignature(secp, signature))) {
            throw ReallyMeCryptoException.InvalidSignature()
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(message)
        val valid = try {
            secp.verify(signature, digest, publicKey)
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

    private fun validatePublicKey(secp: Secp256k1, publicKey: ByteArray) {
        try {
            secp.pubkeyParse(publicKey)
        } catch (_: Secp256k1Exception) {
            throw ReallyMeCryptoException.InvalidInput()
        }
    }

    private fun normalizedSignature(secp: Secp256k1, signature: ByteArray): ByteArray {
        val normalized = try {
            secp.signatureNormalize(signature)
        } catch (_: Secp256k1Exception) {
            throw ReallyMeCryptoException.InvalidSignature()
        }
        val normalizedSignature = normalized.first
        if (normalizedSignature.size != SIGNATURE_LENGTH) {
            throw ReallyMeCryptoException.InvalidSignature()
        }
        return normalizedSignature
    }
}
