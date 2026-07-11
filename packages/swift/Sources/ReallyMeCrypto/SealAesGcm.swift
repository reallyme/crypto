// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

/// AES-256-GCM backed by CryptoKit.
///
/// The package contract uses ciphertext with the 16-byte authentication tag
/// appended and keeps the nonce separate. CryptoKit's combined representation
/// prefixes the nonce, so this wrapper performs the small shape conversion at
/// the package boundary.
public enum ReallyMeAesGcm {
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

        let symmetricKey = SymmetricKey(data: key)
        let cryptoKitNonce: AES.GCM.Nonce
        do {
            cryptoKitNonce = try AES.GCM.Nonce(data: nonce)
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }

        do {
            let sealed = try AES.GCM.seal(
                Data(plaintext),
                using: symmetricKey,
                nonce: cryptoKitNonce,
                authenticating: Data(aad)
            )
            return Array(sealed.ciphertext) + Array(sealed.tag)
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

        let ciphertextLength = ciphertextWithTag.count.subtractingReportingOverflow(tagLength)
        guard !ciphertextLength.overflow else {
            throw ReallyMeCryptoError.invalidInput
        }

        let ciphertext = ciphertextWithTag.prefix(ciphertextLength.partialValue)
        let tag = ciphertextWithTag.suffix(tagLength)
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: Data(ciphertext),
                tag: Data(tag)
            )
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }

        do {
            let plaintext = try AES.GCM.open(
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
