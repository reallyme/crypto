// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

/// AES-GCM backed by CryptoKit.
///
/// The package contract uses ciphertext with the 16-byte authentication tag
/// appended and keeps the nonce separate. CryptoKit's combined representation
/// prefixes the nonce, so this wrapper performs the small shape conversion at
/// the package boundary.
public enum ReallyMeAesGcm {
    public static let aes128KeyLength = 16
    public static let aes192KeyLength = 24
    public static let aes256KeyLength = 32
    public static let keyLength = aes256KeyLength
    public static let nonceLength = 12
    public static let tagLength = 16

    public static func sealAes128Gcm(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        try seal(
            key: key,
            expectedKeyLength: aes128KeyLength,
            nonce: nonce,
            aad: aad,
            plaintext: plaintext
        )
    }

    public static func seal(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        try seal(
            key: key,
            expectedKeyLength: aes256KeyLength,
            nonce: nonce,
            aad: aad,
            plaintext: plaintext
        )
    }

    public static func sealAes192Gcm(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        try seal(
            key: key,
            expectedKeyLength: aes192KeyLength,
            nonce: nonce,
            aad: aad,
            plaintext: plaintext
        )
    }

    public static func openAes128Gcm(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        try open(
            key: key,
            expectedKeyLength: aes128KeyLength,
            nonce: nonce,
            aad: aad,
            ciphertextWithTag: ciphertextWithTag
        )
    }

    public static func open(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        try open(
            key: key,
            expectedKeyLength: aes256KeyLength,
            nonce: nonce,
            aad: aad,
            ciphertextWithTag: ciphertextWithTag
        )
    }

    public static func openAes192Gcm(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        try open(
            key: key,
            expectedKeyLength: aes192KeyLength,
            nonce: nonce,
            aad: aad,
            ciphertextWithTag: ciphertextWithTag
        )
    }

    private static func seal(
        key: [UInt8],
        expectedKeyLength: Int,
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        guard key.count == expectedKeyLength,
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

    private static func open(
        key: [UInt8],
        expectedKeyLength: Int,
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        guard key.count == expectedKeyLength,
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
