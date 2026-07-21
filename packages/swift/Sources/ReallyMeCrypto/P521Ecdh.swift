// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

/// P-521 ECDH backed by CryptoKit.
///
/// Public keys at the SDK boundary are compressed SEC1. The primitive returns
/// the raw 66-byte ECDH x-coordinate; protocols must apply a labelled KDF that
/// binds algorithm and party context before using it as key material.
public enum ReallyMeP521Ecdh {
    public static let secretKeyLength = 66
    public static let compressedPublicKeyLength = 67
    public static let sharedSecretLength = 66

    public static func generateKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        let privateKey = P521.KeyAgreement.PrivateKey()
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
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: Data(secretKey))
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
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: Data(secretKey))
            let peerPublicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: Data(publicKey))
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
            var bytes = sharedSecret.withUnsafeBytes { buffer in
                Array(buffer)
            }
            guard bytes.count == sharedSecretLength else {
                ReallyMeCryptoMemory.bestEffortClear(&bytes)
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
