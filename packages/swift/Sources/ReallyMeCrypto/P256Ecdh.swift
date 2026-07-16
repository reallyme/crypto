// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

/// P-256 ECDH backed by CryptoKit.
///
/// Public keys at the SDK boundary are compressed SEC1. The primitive returns
/// the raw 32-byte ECDH x-coordinate; protocols must apply their own labelled
/// KDF rather than relying on this low-level helper to choose one.
public enum ReallyMeP256Ecdh {
    public static let secretKeyLength = 32
    public static let compressedPublicKeyLength = 33
    public static let sharedSecretLength = 32

    public static func generateKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        let privateKey = P256.KeyAgreement.PrivateKey()
        return (
            publicKey: Array(privateKey.publicKey.compressedRepresentation),
            secretKey: Array(privateKey.rawRepresentation)
        )
    }

    public static func deriveKeyPair(secretKey: [UInt8]) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        (
            publicKey: try derivePublicKey(secretKey: secretKey),
            secretKey: secretKey
        )
    }

    public static func derivePublicKey(secretKey: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == secretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        do {
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(secretKey))
            return Array(privateKey.publicKey.compressedRepresentation)
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    public static func deriveSharedSecret(publicKey: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard publicKey.count == compressedPublicKeyLength,
              secretKey.count == secretKeyLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }
        do {
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(secretKey))
            let peerPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: Data(publicKey))
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            let bytes = sharedSecret.withUnsafeBytes { buffer in
                Array(buffer)
            }
            guard bytes.count == sharedSecretLength else {
                throw ReallyMeCryptoError.providerFailure
            }
            return bytes
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}
