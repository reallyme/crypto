// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

/// X25519 key agreement backed by CryptoKit.
///
/// The package returns the raw 32-byte Diffie-Hellman output. Higher-level
/// protocols must bind it through their own KDF transcript; this primitive does
/// not apply HKDF implicitly because HPKE, MLS, and ratchets label transcripts
/// differently.
public enum ReallyMeX25519 {
    public static let secretKeyLength = 32
    public static let publicKeyLength = 32
    public static let sharedSecretLength = 32

    /// Generates a random X25519 keypair: 32-byte public key, 32-byte secret.
    public static func generateKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return (
            publicKey: Array(privateKey.publicKey.rawRepresentation),
            secretKey: Array(privateKey.rawRepresentation)
        )
    }

    /// Derives an X25519 keypair from a 32-byte secret.
    public static func deriveKeyPair(secretKey: [UInt8]) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        (
            publicKey: try derivePublicKey(secretKey: secretKey),
            secretKey: secretKey
        )
    }

    /// Derives the 32-byte X25519 public key from a 32-byte secret.
    public static func derivePublicKey(secretKey: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == secretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(secretKey))
            return Array(privateKey.publicKey.rawRepresentation)
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    /// Derives the raw 32-byte X25519 shared secret.
    public static func deriveSharedSecret(publicKey: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard publicKey.count == publicKeyLength,
              secretKey.count == secretKeyLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }
        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(secretKey))
            let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKey))
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            var bytes = sharedSecret.withUnsafeBytes { buffer in
                Array(buffer)
            }
            guard bytes.count == sharedSecretLength,
                  bytes.contains(where: { $0 != 0 })
            else {
                ReallyMeCryptoMemory.bestEffortClear(&bytes)
                throw ReallyMeCryptoError.invalidInput
            }
            return bytes
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}
