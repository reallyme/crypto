// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

/// ChaCha20-Poly1305 backed by CryptoKit.
///
/// CryptoKit's combined representation prefixes the nonce. The ReallyMe
/// package contract keeps the nonce separate and returns ciphertext with the
/// 16-byte Poly1305 tag appended.
public enum ReallyMeChaCha20Poly1305 {
    public static let keyLength = 32
    public static let nonceLength = 12
    public static let tagLength = 16

    public static func seal(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        guard key.count == keyLength,
              nonce.count == nonceLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let cryptoKitNonce: ChaChaPoly.Nonce
        do {
            cryptoKitNonce = try ChaChaPoly.Nonce(data: nonce)
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }

        do {
            let sealed = try ChaChaPoly.seal(
                Data(plaintext),
                using: SymmetricKey(data: key),
                nonce: cryptoKitNonce,
                authenticating: Data(aad)
            )
            guard sealed.combined.count >= nonceLength else {
                throw ReallyMeCryptoError.providerFailure
            }
            return Array(sealed.combined.dropFirst(nonceLength))
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw ReallyMeCryptoError.providerFailure
        }
    }

    public static func open(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        guard key.count == keyLength,
              nonce.count == nonceLength,
              ciphertextWithTag.count >= tagLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let combined = Data(nonce) + Data(ciphertextWithTag)
        let sealed: ChaChaPoly.SealedBox
        do {
            sealed = try ChaChaPoly.SealedBox(combined: combined)
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }

        do {
            let plaintext = try ChaChaPoly.open(
                sealed,
                using: SymmetricKey(data: key),
                authenticating: Data(aad)
            )
            return Array(plaintext)
        } catch CryptoKitError.authenticationFailure {
            throw ReallyMeCryptoError.authenticationFailed
        } catch {
            throw ReallyMeCryptoError.providerFailure
        }
    }
}
